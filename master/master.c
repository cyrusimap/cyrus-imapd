/* master.c -- IMAP master process to handle recovery, checkpointing, spawning
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
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
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <inttypes.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#ifndef INADDR_ANY
#define INADDR_ANY 0x00000000
#endif

#if !defined(IPV6_V6ONLY) && defined(IPV6_BINDV6ONLY)
#define IPV6_V6ONLY     IPV6_BINDV6ONLY
#endif

#if defined(HAVE_NETSNMP)
  #include <net-snmp/net-snmp-config.h>
  #include <net-snmp/net-snmp-includes.h>
  #include <net-snmp/agent/net-snmp-agent-includes.h>
#if defined(HAVE_NET_SNMP_AGENT_AGENT_MODULE_CONFIG_H)
    #include <net-snmp/agent/agent_module_config.h>
#endif

  #include "cyrusMasterMIB.h"


  /* Use our own definitions for these */
  #undef TOUPPER
  #undef TOLOWER

#elif defined(HAVE_UCDSNMP)
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

#include "cyr_lock.h"
#include "util.h"
#include "xmalloc.h"
#include "strarray.h"

enum {
    child_table_size = 10000,
    child_table_inc = 100
};

static int verbose = 0;
static int listen_queue_backlog = 32;
static int pidfd = -1;

static int in_shutdown = 0;

const char *MASTER_CONFIG_FILENAME = DEFAULT_MASTER_CONFIG_FILENAME;

#define SERVICE_NONE -1
#define SERVICE_MAX  INT_MAX-10
#define SERVICEPARAM(x) ((x) ? x : "unknown")

#define MAX_READY_FAILS              5
#define MAX_READY_FAIL_INTERVAL     10  /* 10 seconds */

struct service *Services = NULL;
static int allocservices = 0;
int nservices = 0;

struct event {
    char *name;
    struct timeval mark;
    time_t period;
    int hour;
    int min;
    int periodic;
    strarray_t *exec;
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
    enum sstate service_state;  /* SERVICE_STATE_* */
    time_t janitor_deadline;    /* cleanup deadline */
    int si;                     /* Services[] index */
    char *desc;                 /* human readable description for logging */
    struct timeval spawntime;   /* when the centry was allocated */
    time_t sighuptime;          /* when did we send a SIGHUP */;
    struct centry *next;
};
static struct centry *ctable[child_table_size];

static int janitor_frequency = 1;       /* Janitor sweeps per second */
static int janitor_position;            /* Entry to begin at in next sweep */
static struct timeval janitor_mark;     /* Last time janitor did a sweep */

static void limit_fds(rlim_t);
static void schedule_event(struct event *a);
static void child_sighandler_setup(void);

#if HAVE_PSELECT
static sigset_t pselect_sigmask;
#endif

static int myselect(int nfds, fd_set *rfds, fd_set *wfds,
                    fd_set *efds, struct timeval *tout)
{
#if HAVE_PSELECT
    /* pselect() closes the race between SIGCHLD arriving
    * and select() sleeping for up to 10 seconds. */
    struct timespec ts, *tsptr = NULL;

    if (tout) {
        ts.tv_sec = tout->tv_sec;
        ts.tv_nsec = tout->tv_usec * 1000;
        tsptr = &ts;
    }
    return pselect(nfds, rfds, wfds, efds, tsptr, &pselect_sigmask);
#else
    return select(nfds, rfds, wfds, efds, tout);
#endif
}

EXPORTED void fatal(const char *msg, int code)
{
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");
    exit(code);
}

static void event_free(struct event *a)
{
    if (a->exec) {
        strarray_free(a->exec);
        a->exec = NULL;
    }
    free(a->name);
    free(a);
}

static void get_daemon(char *path, size_t size, const strarray_t *cmd)
{
    if (!size) return;
    if (cmd->data[0][0] == '/') {
        /* master lacks strlcpy, due to no libcyrus */
        strncpy(path, cmd->data[0], size - 1);
    }
    else snprintf(path, size, "%s/%s", LIBEXEC_DIR, cmd->data[0]);
    path[size-1] = '\0';
}

static void get_prog(char *path, size_t size, const strarray_t *cmd)
{
    if (!size) return;
    if (cmd->data[0][0] == '/') {
        /* master lacks strlcpy, due to no libcyrus */
        strncpy(path, cmd->data[0], size - 1);
    }
    else snprintf(path, size, "%s/%s", SBIN_DIR, cmd->data[0]);
    path[size-1] = '\0';
}

static void get_executable(char *path, size_t size, const strarray_t *cmd)
{
    struct stat statbuf;

    if (!size) return;
    get_daemon(path, size, cmd);
    if (!stat(path, &statbuf)) return;
    get_prog(path, size, cmd);
    if (!stat(path, &statbuf)) return;
    /* XXX - abort? */
}

static void get_statsock(int filedes[2])
{
    int r, fdflags;

    r = pipe(filedes);
    if (r != 0)
        fatalf(1, "couldn't create status socket: %m");

    /* we don't want the master blocking on reads */
    fdflags = fcntl(filedes[0], F_GETFL, 0);
    if (fdflags != -1) fdflags = fcntl(filedes[0], F_SETFL,
                                       fdflags | O_NONBLOCK);
    if (fdflags == -1)
        fatalf(1, "unable to set non-blocking: %m");
    /* we don't want the services to be able to read from it */
    fdflags = fcntl(filedes[0], F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(filedes[0], F_SETFD,
                                       fdflags | FD_CLOEXEC);
    if (fdflags == -1)
        fatalf(1, "unable to set close-on-exec: %m");
}

static int cap_bind(int socket, struct sockaddr *addr, socklen_t length)
{
    int r;

    set_caps(BEFORE_BIND, /*is_master*/1);
    r = bind(socket, addr, length);
    set_caps(AFTER_BIND, /*is_master*/1);

    return r;
}

/* Return a new 'centry', by malloc'ing it. */
static struct centry *centry_alloc(void)
{
    struct centry *t;

    t = xzmalloc(sizeof(*t));
    t->si = SERVICE_NONE;
    gettimeofday(&t->spawntime, NULL);
    t->sighuptime = (time_t)-1;

    return t;
}

static void centry_set_name(struct centry *c, const char *type,
                            const char *name, const char *path)
{
    free(c->desc);
    if (name && path)
        c->desc = strconcat("type:", type, " name:", name, " path:", path, NULL);
    else
        c->desc = strconcat("type:", type, NULL);
}

static char *centry_describe(const struct centry *c, pid_t pid)
{
    struct buf desc = BUF_INITIALIZER;

    if (!c) {
        buf_appendcstr(&desc, "unknown process");
    }
    else {
        struct timeval now;
        gettimeofday(&now, NULL);
        buf_printf(&desc, "process %s age:%.3fs",
                   c->desc, timesub(&c->spawntime, &now));
    }
    buf_printf(&desc, " pid:%d", (int)pid);
    return buf_release(&desc);
}

/* free a centry */
static void centry_free(struct centry *c)
{
    free(c->desc);
    free(c);
}

/* add a centry to the global table of all
 * centries, using the given pid as the key */
static void centry_add(struct centry *c, pid_t p)
{
    c->pid = p;
    c->next = ctable[p % child_table_size];
    ctable[p % child_table_size] = c;
}

/* find a centry in the global table, using the
 * given pid as the key.  Returns NULL if not
 * found. */
static struct centry *centry_find(pid_t p)
{
    struct centry *c;

    c = ctable[p % child_table_size];
    while (c && c->pid != p)
        c = c->next;
    return c;
}

static void centry_set_state(struct centry *c, enum sstate state)
{
    c->service_state = state;
    if (state == SERVICE_STATE_DEAD)
        c->janitor_deadline = time(NULL) + 2;
}

/*
 * Parse the "listen" parameter as one of the forms:
 *
 * hostname
 * hostname ':' port
 * ipv4-address
 * ipv4-address ':' port
 * '[' ipv4-address ']'
 * '[' ipv4-address ']' ':' port
 * '[' ipv6-address ']'
 * '[' ipv6-address ']' ':' port
 *
 * Returns 0 on success with one or more of *@hostp and *@portp set
 * to new strings which must be free()d by the caller, or -1 on error.
 */
static int parse_inet_listen(const char *listen,
                             char **hostp, char **portp)
{
    const char *cp;

    *portp = NULL;
    *hostp = NULL;
    if (listen[0] == '[') {
        cp = strrchr(listen, ']');
        if (!cp)
            return -1;
        cp++;
        if (*cp == ':') {
            if (!cp[1])
                return -1;
            *hostp = xstrndup(listen+1, (cp - listen - 2));
            *portp = xstrdup(cp+1);
            return 0;
        }
        if (!*cp) {
            *hostp = xstrndup(listen+1, (cp - listen - 2));
            /* no port specified */
            return 0;
        }
        return -1;
    }

    cp = strrchr(listen, ':');
    if (cp) {
        if (!cp[1])
            return -1;
        *hostp = xstrndup(listen, (cp - listen));
        *portp = xstrdup(cp+1);
        return 0;
    }

    /* no host specified */
    *portp = xstrdup(listen);
    return 0;
}

static int verify_service_file(const strarray_t *filename)
{
    char path[PATH_MAX];
    struct stat statbuf;

    get_executable(path, sizeof(path), filename);
    if (stat(path, &statbuf)) return 0;
    if (! S_ISREG(statbuf.st_mode)) return 0;
    return statbuf.st_mode & S_IXUSR;
}

static void service_forget_exec(struct service *s)
{
    if (s->exec) {
        /* Only free the service info on the primary */
        if (s->associate == 0) {
            strarray_free(s->exec);
        }
        s->exec = NULL;
    }
}

static struct service *service_add(const struct service *proto)
{
    struct service *s;

    if (nservices == allocservices) {
        if (allocservices > SERVICE_MAX - 5)
            fatal("out of service structures, please restart", EX_UNAVAILABLE);
        Services = xrealloc(Services,
                           (allocservices+=5) * sizeof(struct service));
    }
    s = &Services[nservices++];

    if (proto)
        memcpy(s, proto, sizeof(struct service));
    else {
        memset(s, 0, sizeof(struct service));
        s->socket = -1;
        s->stat[0] = -1;
        s->stat[1] = -1;
    }

    return s;
}

static void service_create(struct service *s)
{
    struct service service0, service;
    struct addrinfo hints, *res0, *res;
    int error, nsocket = 0;
    struct sockaddr_un sunsock;
    mode_t oldumask;
    int on = 1;
    int res0_is_local = 0;
    int r;

    if (s->associate > 0)
        return;                 /* service is already activated */

    if (!s->listen)
        return;                 /* service is a daemon, no listener */

    if (!s->name)
        fatal("Serious software bug found: service_create() called on unnamed service!",
                EX_SOFTWARE);

    if (s->listen[0] == '/') { /* unix socket */
        res0_is_local = 1;
        res0 = (struct addrinfo *)xzmalloc(sizeof(struct addrinfo));
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
        char *port;
        char *listen_addr;

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        if (!strcmp(s->proto, "tcp")) {
            hints.ai_family = PF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
        } else if (!strcmp(s->proto, "tcp4")) {
            hints.ai_family = PF_INET;
            hints.ai_socktype = SOCK_STREAM;
#ifdef PF_INET6
        } else if (!strcmp(s->proto, "tcp6")) {
            hints.ai_family = PF_INET6;
            hints.ai_socktype = SOCK_STREAM;
#endif
        } else if (!strcmp(s->proto, "udp")) {
            hints.ai_family = PF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
        } else if (!strcmp(s->proto, "udp4")) {
            hints.ai_family = PF_INET;
            hints.ai_socktype = SOCK_DGRAM;
#ifdef PF_INET6
        } else if (!strcmp(s->proto, "udp6")) {
            hints.ai_family = PF_INET6;
            hints.ai_socktype = SOCK_DGRAM;
#endif
        } else {
            syslog(LOG_INFO, "invalid proto '%s', disabling %s",
                   s->proto, s->name);
            service_forget_exec(s);
            return;
        }

        if (parse_inet_listen(s->listen, &listen_addr, &port) < 0) {
            syslog(LOG_ERR, "invalid listen '%s', disabling %s",
                   s->listen, s->name);
            service_forget_exec(s);
            return;
        }

        error = getaddrinfo(listen_addr, port, &hints, &res0);

        free(listen_addr);
        free(port);

        if (error) {
            syslog(LOG_INFO, "%s, disabling %s", gai_strerror(error), s->name);
            service_forget_exec(s);
            return;
        }
    }

    memcpy(&service0, s, sizeof(struct service));

    for (res = res0; res; res = res->ai_next) {
        if (s->socket >= 0) {
            memcpy(&service, &service0, sizeof(struct service));
            s = &service;
        }

        s->family = res->ai_family;
        switch (s->family) {
        case AF_UNIX:   s->familyname = "unix"; break;
        case AF_INET:   s->familyname = "ipv4"; break;
        case AF_INET6:  s->familyname = "ipv6"; break;
        default:        s->familyname = "unknown"; break;
        }

        if (verbose > 2) {
            syslog(LOG_DEBUG, "activating service %s/%s",
                s->name, s->familyname);
        }

        s->socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s->socket < 0) {
            syslog(LOG_ERR, "unable to open %s/%s socket: %m",
                s->name, s->familyname);
            continue;
        }

        /* allow reuse of address */
        r = setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR,
                       (void *) &on, sizeof(on));
        if (r < 0) {
            syslog(LOG_ERR, "unable to setsocketopt(SO_REUSEADDR) service %s/%s: %m",
                s->name, s->familyname);
        }
#if defined(IPV6_V6ONLY) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
        if (res->ai_family == AF_INET6) {
            r = setsockopt(s->socket, IPPROTO_IPV6, IPV6_V6ONLY,
                           (void *) &on, sizeof(on));
            if (r < 0) {
                syslog(LOG_ERR, "unable to setsocketopt(IPV6_V6ONLY) service %s/%s: %m",
                    s->name, s->familyname);
            }
        }
#endif

        /* set IP ToS if supported */
#if defined(SOL_IP) && defined(IP_TOS)
        if (s->family == AF_INET || s->family == AF_INET6) {
            r = setsockopt(s->socket, SOL_IP, IP_TOS,
                           (void *) &config_qosmarking,
                           sizeof(config_qosmarking));
            if (r < 0) {
                syslog(LOG_WARNING,
                       "unable to setsocketopt(IP_TOS) service %s/%s: %m",
                       s->name, s->familyname);
            }
        }
#endif

        oldumask = umask((mode_t) 0); /* for linux */
        r = cap_bind(s->socket, res->ai_addr, res->ai_addrlen);
        umask(oldumask);
        if (r < 0) {
            syslog(LOG_ERR, "unable to bind to %s/%s socket: %m",
                s->name, s->familyname);
            xclose(s->socket);
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
            syslog(LOG_ERR, "unable to listen to %s/%s socket: %m",
                s->name, s->familyname);
            xclose(s->socket);
            continue;
        }

        s->ready_workers = 0;
        s->associate = nsocket;

        get_statsock(s->stat);

        if (s == &service)
            service_add(s);
        nsocket++;
    }
    if (res0) {
        if(res0_is_local)
            free(res0);
        else
            freeaddrinfo(res0);
    }
    if (nsocket <= 0) {
        syslog(LOG_ERR, "unable to create %s listener socket: %m", s->name);
        service_forget_exec(s);
        return;
    }
}

static int decode_wait_status(struct centry *c, pid_t pid, int status)
{
    int failed = 0;
    char *desc = centry_describe(c, pid);

    if (WIFEXITED(status)) {
        if (!WEXITSTATUS(status)) {
            syslog(LOG_DEBUG, "%s exited normally", desc);
        }
        else {
            syslog(LOG_ERR, "%s exited, status %d",
                   desc, WEXITSTATUS(status));
            failed = 1;
        }
    }

    if (WIFSIGNALED(status)) {
        const char *signame = strsignal(WTERMSIG(status));
        if (!signame)
            signame = "unknown signal";
#ifdef WCOREDUMP
        syslog(LOG_ERR, "%s signaled to death by signal %d (%s%s)",
               desc, WTERMSIG(status), signame,
               WCOREDUMP(status) ? ", core dumped" : "");
        failed = WCOREDUMP(status) ? 2 : 1;
#else
        syslog(LOG_ERR, "%s signaled to death by %s %d",
               desc, signame, WTERMSIG(status));
        failed = 1;
#endif
    }
    free(desc);
    return failed;
}

static void run_startup(const char *name, const strarray_t *cmd)
{
    pid_t pid;
    int status;
    struct centry *c;
    char path[PATH_MAX];

    get_executable(path, sizeof(path), cmd);

    switch (pid = fork()) {
    case -1:
        fatalf(1, "can't fork process to run startup: %m");
        break;

    case 0:
        /* Child - Release our pidfile lock. */
        xclose(pidfd);

        set_caps(AFTER_FORK, /*is_master*/1);

        child_sighandler_setup();

        limit_fds(256);

        syslog(LOG_DEBUG, "about to exec %s", path);
        execv(path, cmd->data);
        fatalf(EX_OSERR, "can't exec %s for startup: %m", path);

    default: /* parent */
        if (waitpid(pid, &status, 0) < 0) {
            syslog(LOG_ERR, "waitpid(): %m");
            return;
        }
        c = centry_alloc();
        centry_set_name(c, "START", name, path);
        if (decode_wait_status(c, pid, status))
            fatal("can't run startup", 1);
        centry_free(c);
        break;
    }
}

static void fcntl_unset(int fd, int flag)
{
    int fdflags = fcntl(fd, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD,
                                       fdflags & ~flag);
    if (fdflags == -1) {
        syslog(LOG_ERR, "fcntl(): unable to unset %d: %m", flag);
    }
}

static int service_is_fork_limited(struct service *s)
{
/* The longest period for which we will ignore the service */
#define FORKRATE_INTERVAL   0.4 /* seconds */
/* How much the forkrate estimator decays, as a proportion, per second */
#define FORKRATE_ALPHA          0.5     /* per second */
    struct timeval now;
    double interval;

    if (!s->maxforkrate)
        return 0;

    gettimeofday(&now, 0);
    interval = timesub(&s->last_interval_start, &now);
    /* update our fork rate */
    if (interval > 0.0) {
        double f = pow(FORKRATE_ALPHA, interval);
        s->forkrate = f * s->forkrate +
                      (1.0-f) * (s->interval_forks/interval);
        s->interval_forks = 0;
        s->last_interval_start = now;
    }
    else if (interval < 0.0) {
        /*
         * NTP or similar moved the time-of-day clock backwards more
         * than the interval we asked to be delayed for.  Given that, we
         * have no basis for updating forkrate and must reset our rate
         * estimating state.  Let's just hope this is a rare event.
         */
        s->interval_forks = 0;
        s->last_interval_start = now;
        syslog(LOG_WARNING, "time of day clock went backwards");
    }

    /* If we've been busy lately, we will refuse to fork! */
    /* (We schedule a wakeup call for sometime soon though to be
     * sure that we don't wait to do the fork that is required forever! */
    if ((unsigned int)s->forkrate >= s->maxforkrate) {
        struct event *evt = (struct event *) xzmalloc(sizeof(struct event));

        evt->name = xstrdup("forkrate wakeup call");
        evt->mark = now;
        timeval_add_double(&evt->mark, FORKRATE_INTERVAL);

        schedule_event(evt);

        return 1;
    }
    return 0;
}

static void spawn_service(int si)
{
    pid_t p;
    int i;
    char path[PATH_MAX];
    static char name_env[100], name_env2[100], name_env3[100];
    struct centry *c;
    struct service *s = &Services[si];

    if (!s->name) {
        fatal("Serious software bug found: spawn_service() called on unnamed service!",
                EX_SOFTWARE);
    }

    if (service_is_fork_limited(s))
        return;

    get_executable(path, sizeof(path), s->exec);

    switch (p = fork()) {
    case -1:
        syslog(LOG_ERR, "can't fork process to run service %s/%s: %m",
            s->name, s->familyname);
        break;

    case 0:
        if (verbose > 2) {
            syslog(LOG_DEBUG, "forked process to run service %s/%s",
                s->name, s->familyname);
        }

        /* Child - Release our pidfile lock. */
        xclose(pidfd);

        set_caps(AFTER_FORK, /*is_master*/1);

        child_sighandler_setup();

        if (s->listen) {
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
        }
        else {
            snprintf(name_env3, sizeof(name_env3), "CYRUS_ISDAEMON=1");
            putenv(name_env3);
        }
        limit_fds(s->maxfds);

        /* close all listeners */
        for (i = 0; i < nservices; i++) {
            xclose(Services[i].socket);
            xclose(Services[i].stat[0]);
            xclose(Services[i].stat[1]);
        }

        syslog(LOG_DEBUG, "about to exec %s", path);

        /* add service name to environment */
        snprintf(name_env, sizeof(name_env), "CYRUS_SERVICE=%s", s->name);
        putenv(name_env);
        snprintf(name_env2, sizeof(name_env2), "CYRUS_ID=%d", s->associate);
        putenv(name_env2);

        execv(path, s->exec->data);
        syslog(LOG_ERR, "couldn't exec %s: %m", path);
        exit(EX_OSERR);

    default:                    /* parent */
        s->ready_workers++;
        s->interval_forks++;
        s->nforks++;
        s->nactive++;

        /* add to child table */
        c = centry_alloc();
        centry_set_name(c, s->listen ? "SERVICE" : "DAEMON", s->name, path);
        c->si = si;
        centry_set_state(c, SERVICE_STATE_READY);
        centry_add(c, p);
        break;
    }

}

static void schedule_event(struct event *a)
{
    struct event *ptr;

    if (! a->name)
        fatal("Serious software bug found: schedule_event() called on unnamed event!",
                EX_SOFTWARE);

    if (!schedule || timesub(&schedule->mark, &a->mark) < 0.0) {
        a->next = schedule;
        schedule = a;

        return;
    }
    for (ptr = schedule;
         ptr->next && timesub(&a->mark, &ptr->next->mark) <= 0.0;
         ptr = ptr->next) ;

    /* insert a */
    a->next = ptr->next;
    ptr->next = a;
}

static void spawn_schedule(struct timeval now)
{
    struct event *a, *b;
    int i;
    char path[PATH_MAX];
    pid_t p;
    struct centry *c;

    a = NULL;
    /* update schedule accordingly */
    while (schedule && timesub(&now, &schedule->mark) <= 0.0) {
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
            get_executable(path, sizeof(path), a->exec);
            switch (p = fork()) {
            case -1:
                syslog(LOG_CRIT,
                       "can't fork process to run event %s", a->name);
                break;

            case 0:
                /* Child - Release our pidfile lock. */
                xclose(pidfd);

                set_caps(AFTER_FORK, /*is_master*/1);

                /* close all listeners */
                for (i = 0; i < nservices; i++) {
                    xclose(Services[i].socket);
                    xclose(Services[i].stat[0]);
                    xclose(Services[i].stat[1]);
                }
                limit_fds(256);

                syslog(LOG_DEBUG, "about to exec %s", path);
                execv(path, a->exec->data);
                syslog(LOG_ERR, "can't exec %s on schedule: %m", path);
                exit(EX_OSERR);
                break;

            default:
                /* we don't wait for it to complete */

                /* add to child table */
                c = centry_alloc();
                centry_set_name(c, "EVENT", a->name, path);
                centry_set_state(c, SERVICE_STATE_READY);
                centry_add(c, p);
                break;
            }
        } /* a->exec */

        /* reschedule as needed */
        b = a->next;
        if (a->period) {
            if(a->periodic) {
                a->mark = now;
                a->mark.tv_sec += a->period;
            } else {
                struct tm *tm;
                int delta;
                /* Daily Event */
                while (timesub(&now, &a->mark) <= 0.0)
                    a->mark.tv_sec += a->period;
                /* check for daylight savings fuzz... */
                tm = localtime(&a->mark.tv_sec);
                if (tm->tm_hour != a->hour || tm->tm_min != a->min) {
                    /* calculate the same time on the new day */
                    tm->tm_hour = a->hour;
                    tm->tm_min = a->min;
                    delta = mktime(tm) - a->mark.tv_sec;
                    /* bring it within half a period either way */
                    while (delta > (a->period/2)) delta -= a->period;
                    while (delta < -(a->period/2)) delta += a->period;
                    /* update the time */
                    a->mark.tv_sec += delta;
                    /* and let us know about the change */
                    syslog(LOG_NOTICE, "timezone shift for %s - altering schedule by %d seconds", a->name, delta);
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

static void reap_child(void)
{
    int status;
    pid_t pid;
    struct centry *c;
    struct service *s;
    int failed;

    while ((pid = waitpid((pid_t) -1, &status, WNOHANG)) > 0) {

        /* account for the child */
        c = centry_find(pid);

        failed = decode_wait_status(c, pid, status);

        if (c) {
            s = ((c->si) != SERVICE_NONE) ? &Services[c->si] : NULL;

            /* paranoia */
            switch (c->service_state) {
            case SERVICE_STATE_READY:
            case SERVICE_STATE_BUSY:
            case SERVICE_STATE_UNKNOWN:
            case SERVICE_STATE_DEAD:
                break;
            default:
                syslog(LOG_CRIT,
                       "service %s/%s pid %d in ILLEGAL STATE: exited. Serious "
                       "software bug or memory corruption detected!",
                       s ? SERVICEPARAM(s->name) : "unknown",
                       s ? SERVICEPARAM(s->familyname) : "unknown", pid);
                centry_set_state(c, SERVICE_STATE_UNKNOWN);
            }
            if (s) {
                /* update counters for known services */
                switch (c->service_state) {
                case SERVICE_STATE_READY:
                    s->nactive--;
                    s->ready_workers--;
                    if (!in_shutdown && failed) {
                        time_t now = time(NULL);

                        syslog(LOG_WARNING,
                               "service %s/%s pid %d in READY state: "
                               "terminated abnormally",
                               SERVICEPARAM(s->name),
                               SERVICEPARAM(s->familyname), pid);
                        if (now - s->lastreadyfail > MAX_READY_FAIL_INTERVAL) {
                            s->nreadyfails = 0;
                        }
                        s->lastreadyfail = now;
                        if (++s->nreadyfails >= MAX_READY_FAILS && s->exec) {
                            syslog(LOG_ERR, "too many failures for "
                                   "service %s/%s, disabling until next SIGHUP",
                                   SERVICEPARAM(s->name),
                                   SERVICEPARAM(s->familyname));
                            service_forget_exec(s);
                            xclose(s->socket);
                        }
                    }
                    break;

                case SERVICE_STATE_DEAD:
                    /* uh? either we got duplicate signals, or we are now MT */
                    syslog(LOG_WARNING,
                           "service %s/%s pid %d in DEAD state: "
                           "receiving duplicate signals",
                           SERVICEPARAM(s->name),
                           SERVICEPARAM(s->familyname), pid);
                    break;

                case SERVICE_STATE_BUSY:
                    s->nactive--;
                    if (!in_shutdown && failed) {
                        syslog(LOG_DEBUG,
                               "service %s/%s pid %d in BUSY state: "
                               "terminated abnormally",
                               SERVICEPARAM(s->name),
                               SERVICEPARAM(s->familyname), pid);
                    }
                    break;

                case SERVICE_STATE_UNKNOWN:
                    s->nactive--;
                    syslog(LOG_WARNING,
                           "service %s/%s pid %d in UNKNOWN state: exited",
                           SERVICEPARAM(s->name),
                           SERVICEPARAM(s->familyname), pid);
                    break;
                default:
                    /* Shouldn't get here */
                    break;
                }
            } else {
                /* children from spawn_schedule (events) or
                 * children of services removed by reread_conf() */
                if (c->service_state != SERVICE_STATE_READY) {
                    syslog(LOG_WARNING,
                           "unknown service pid %d in state %d: exited "
                           "(maybe using a service as an event, "
                           "or a service was removed by SIGHUP?)",
                           pid, c->service_state);
                }
            }
            centry_set_state(c, SERVICE_STATE_DEAD);
        } else {
            /* Are we multithreaded now? we don't know this child */
            syslog(LOG_ERR,
                   "received SIGCHLD from unknown child pid %d, ignoring",
                   pid);
            /* FIXME: is this something we should take lightly? */
        }
        if (verbose && c && (c->si != SERVICE_NONE))
            syslog(LOG_DEBUG, "service %s/%s now has %d ready workers",
                    SERVICEPARAM(Services[c->si].name),
                    SERVICEPARAM(Services[c->si].familyname),
                    Services[c->si].ready_workers);
    }
}

static void init_janitor(struct timeval now)
{
    struct event *evt = (struct event *) xzmalloc(sizeof(struct event));

    janitor_mark = now;
    janitor_position = 0;

    evt->name = xstrdup("janitor periodic wakeup call");
    evt->period = 10;
    evt->periodic = 1;
    evt->mark = janitor_mark;
    schedule_event(evt);
}

static void child_janitor(struct timeval now)
{
    int i;
    struct centry **p;
    struct centry *c;

    /* Estimate the number of entries to clean up in this sweep */
    if (now.tv_sec > janitor_mark.tv_sec + 1) {
        /* overflow protection */
        i = child_table_size;
    } else {
        double n;

        n = child_table_size * janitor_frequency * timesub(&janitor_mark, &now);
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
                if (c->janitor_deadline < now.tv_sec) {
                    *p = c->next;
                    centry_free(c);
                } else {
                    p = &((*p)->next);
                }
            } else {
                time_t delay = (c->sighuptime != (time_t)-1) ?
                    time(NULL) - c->sighuptime : 0;

                if (delay >= 30) {
                    /* client not yet logged out ? */
                    struct service *s = ((c->si) != SERVICE_NONE) ?
                        &Services[c->si] : NULL;

                    syslog(LOG_INFO, "service %s/%s pid %d in state %d has not "
                        "yet been recycled since SIGHUP was sent (%ds ago)",
                        s ? SERVICEPARAM(s->name) : "unknown",
                        s ? SERVICEPARAM(s->familyname) : "unknown",
                        c->pid, c->service_state, (int)delay);

                    /* no need to log it more than once */
                    c->sighuptime = (time_t)-1;
                }
                p = &((*p)->next);
            }
        }
    }
}

/* Allow a clean shutdown on SIGQUIT, SIGTERM or SIGINT */
static volatile sig_atomic_t gotsigquit = 0;

static void sigquit_handler(int sig __attribute__((unused)))
{
    gotsigquit = 1;
}

static void begin_shutdown(void)
{
    /* Set a flag so main loop knows to shut down when
       all children have exited.  Note, we will be called
       twice as we send SIGTERM to our own process group. */
    if (in_shutdown)
        return;
    in_shutdown = 1;
    syslog(LOG_INFO, "attempting clean shutdown on signal");

#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
    /* tell master agent we're exiting */
    snmp_shutdown("cyrusMaster");
#endif

    /* send our process group a SIGTERM */
    if (kill(0, SIGTERM) < 0) {
        syslog(LOG_ERR, "begin_shutdown: kill(0, SIGTERM): %m");
    }
}

static volatile sig_atomic_t gotsigchld = 0;

static void sigchld_handler(int sig __attribute__((unused)))
{
    gotsigchld = 1;
}

static volatile int gotsighup = 0;

static void sighup_handler(int sig __attribute__((unused)))
{
    gotsighup = 1;
}

static void sigalrm_handler(int sig __attribute__((unused)))
{
    return;
}

static void sighandler_setup(void)
{
    struct sigaction action;
    sigset_t siglist;

    memset(&siglist, 0, sizeof(siglist));
    sigemptyset(&siglist);
    sigaddset(&siglist, SIGHUP);
    sigaddset(&siglist, SIGALRM);
    sigaddset(&siglist, SIGQUIT);
    sigaddset(&siglist, SIGTERM);
    sigaddset(&siglist, SIGINT);
    sigaddset(&siglist, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &siglist, NULL);

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);

    action.sa_handler = sighup_handler;
#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif
    if (sigaction(SIGHUP, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGHUP: %m");

    action.sa_handler = sigalrm_handler;
    if (sigaction(SIGALRM, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGALRM: %m");

    /* Allow a clean shutdown on any of SIGQUIT, SIGINT or SIGTERM */
    action.sa_handler = sigquit_handler;
    if (sigaction(SIGQUIT, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGQUIT: %m");
    if (sigaction(SIGTERM, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGTERM: %m");
    if (sigaction(SIGINT, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGINT: %m");

    action.sa_flags |= SA_NOCLDSTOP;
    action.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &action, NULL) < 0)
        fatalf(1, "unable to install signal handler for SIGCHLD: %m");

#if HAVE_PSELECT
    /* block SIGCHLD, and set up pselect_sigmask so SIGCHLD
     * will be unblocked again inside pselect().  Ditto SIGQUIT.  */
    sigemptyset(&siglist);
    sigaddset(&siglist, SIGCHLD);
    sigaddset(&siglist, SIGQUIT);
    sigaddset(&siglist, SIGINT);
    sigaddset(&siglist, SIGTERM);
    sigprocmask(SIG_BLOCK, &siglist, &pselect_sigmask);
#endif
}

static void child_sighandler_setup(void)
{
#if HAVE_PSELECT
    /*
     * We need to explicitly reset our SIGQUIT handler to the default
     * action.  This happens at execv() time, but in the small window
     * between fork() and execv() any SIGQUIT signal delivered will be
     * caught, and the gotsigquit flag set, but that flag is then
     * completely ignored.  Ditto SIGINT and SIGTERM.
     */
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGQUIT, &action, NULL) < 0) {
        syslog(LOG_ERR, "unable to remove signal handler for SIGQUIT: %m");
        exit(EX_TEMPFAIL);
    }
    if (sigaction(SIGINT, &action, NULL) < 0) {
        syslog(LOG_ERR, "unable to remove signal handler for SIGINT: %m");
        exit(EX_TEMPFAIL);
    }
    if (sigaction(SIGTERM, &action, NULL) < 0) {
        syslog(LOG_ERR, "unable to remove signal handler for SIGTERM: %m");
        exit(EX_TEMPFAIL);
    }

    /* Unblock SIGCHLD et al in the child */
    sigprocmask(SIG_SETMASK, &pselect_sigmask, NULL);
#endif
}

/*
 * Receives a message from a service.
 *
 * Returns zero if all goes well
 * 1 if no msg available
 * 2 if bad message received (incorrectly sized)
 * -1 on error (errno set)
 *
 * TODO: should use retry_read() which has almost the
 * exact same semantics apart from the return value.
 */
static int read_msg(int fd, struct notify_message *msg)
{
    ssize_t r = 0;
    size_t off = 0;
    int s = sizeof(struct notify_message);

    while (s > 0) {
        do
            r = read(fd, ((char *)msg) + off, s);
        while ((r == -1) && (errno == EINTR));
        if (r <= 0) break;
        s -= r;
        off += r;
    }
    if ( ((r == 0) && (off == 0)) ||
         ((r == -1) && (errno == EAGAIN)) )
        return 1;
    if (r == -1) return -1;
    if (s != 0) return 2;
    return 0;
}

static void process_msg(int si, struct notify_message *msg)
{
    struct centry *c;
    /* si must NOT point to an invalid service */
    struct service *s = &Services[si];

    c = centry_find(msg->service_pid);

    /* Did we find it? */
    if (!c) {
        /* If we don't know about the child, that means it has expired from
         * the child list, due to large message delivery delays.  This is
         * indeed possible, although it is rare (Debian bug report).
         *
         * Note that this analysis depends on master's single-threaded
         * nature */
        syslog(LOG_WARNING,
                "service %s/%s pid %d: receiving messages from long dead children",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), msg->service_pid);
        /* re-add child to list */
        c = centry_alloc();
        centry_set_name(c, "ZOMBIE", NULL, NULL);
        c->si = si;
        centry_set_state(c, SERVICE_STATE_DEAD);
        centry_add(c, msg->service_pid);
    }

    /* paranoia */
    if (si != c->si) {
        syslog(LOG_ERR,
               "service %s/%s pid %d: changing from service %s/%s due to received message",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid,
               ((c->si != SERVICE_NONE) ? SERVICEPARAM(Services[c->si].name) : "unknown"),
               ((c->si != SERVICE_NONE) ? SERVICEPARAM(Services[c->si].familyname) : "unknown"));
        c->si = si;
    }
    switch (c->service_state) {
    case SERVICE_STATE_UNKNOWN:
        syslog(LOG_WARNING,
               "service %s/%s pid %d in UNKNOWN state: processing message 0x%x",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid, msg->message);
        break;
    case SERVICE_STATE_READY:
    case SERVICE_STATE_BUSY:
    case SERVICE_STATE_DEAD:
        break;
    default:
        syslog(LOG_CRIT,
               "service %s/%s pid %d in ILLEGAL state: detected. Serious software bug or memory corruption uncloaked while processing message 0x%x from child!",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid, msg->message);
        centry_set_state(c, SERVICE_STATE_UNKNOWN);
        break;
    }

    /* process message, according to state machine */
    switch (msg->message) {
    case MASTER_SERVICE_AVAILABLE:
        switch (c->service_state) {
        case SERVICE_STATE_READY:
            /* duplicate message? */
            syslog(LOG_WARNING,
                   "service %s/%s pid %d in READY state: sent available message but it is already ready",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_UNKNOWN:
            /* since state is unknown, error in non-DoS way, i.e.
             * we don't increment ready_workers */
            syslog(LOG_DEBUG,
                   "service %s/%s pid %d in UNKNOWN state: now available and in READY state",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            centry_set_state(c, SERVICE_STATE_READY);
            break;

        case SERVICE_STATE_BUSY:
            if (verbose)
                syslog(LOG_DEBUG,
                       "service %s/%s pid %d in BUSY state: now available and in READY state",
                       SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            centry_set_state(c, SERVICE_STATE_READY);
            s->ready_workers++;
            break;

        case SERVICE_STATE_DEAD:
            /* echoes from the past... just ignore */
            break;

        default:
            /* Shouldn't get here */
            break;
        }
        break;

    case MASTER_SERVICE_UNAVAILABLE:
        switch (c->service_state) {
        case SERVICE_STATE_BUSY:
            /* duplicate message? */
            syslog(LOG_WARNING,
                   "service %s/%s pid %d in BUSY state: sent unavailable message but it is already busy",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_UNKNOWN:
            syslog(LOG_DEBUG,
                   "service %s/%s pid %d in UNKNOWN state: now unavailable and in BUSY state",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            centry_set_state(c, SERVICE_STATE_BUSY);
            break;

        case SERVICE_STATE_READY:
            if (verbose)
                syslog(LOG_DEBUG,
                       "service %s/%s pid %d in READY state: now unavailable and in BUSY state",
                       SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            centry_set_state(c, SERVICE_STATE_BUSY);
            s->ready_workers--;
            break;

        case SERVICE_STATE_DEAD:
            /* echoes from the past... just ignore */
            break;

        default:
            /* Shouldn't get here */
            break;
        }
        break;

    case MASTER_SERVICE_CONNECTION:
        switch (c->service_state) {
        case SERVICE_STATE_BUSY:
            s->nconnections++;
            if (verbose)
                syslog(LOG_DEBUG,
                       "service %s/%s pid %d in BUSY state: now serving connection",
                       SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_UNKNOWN:
            s->nconnections++;
            centry_set_state(c, SERVICE_STATE_BUSY);
            syslog(LOG_DEBUG,
                   "service %s/%s pid %d in UNKNOWN state: now in BUSY state and serving connection",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_READY:
            syslog(LOG_ERR,
                   "service %s/%s pid %d in READY state: reported new connection, forced to BUSY state",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            /* be resilient on face of a bogon source, so lets err to the side
             * of non-denial-of-service */
            centry_set_state(c, SERVICE_STATE_BUSY);
            s->nconnections++;
            s->ready_workers--;
            break;

        case SERVICE_STATE_DEAD:
            /* echoes from the past... do the accounting */
            s->nconnections++;
            break;

        default:
            /* Shouldn't get here */
            break;
        }
        break;

    case MASTER_SERVICE_CONNECTION_MULTI:
        switch (c->service_state) {
        case SERVICE_STATE_READY:
            s->nconnections++;
            if (verbose)
                syslog(LOG_DEBUG,
                       "service %s/%s pid %d in READY state: serving one more multi-threaded connection",
                       SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_BUSY:
            syslog(LOG_ERR,
                   "service %s/%s pid %d in BUSY state: serving one more multi-threaded connection, forced to READY state",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            /* be resilient on face of a bogon source, so lets err to the side
             * of non-denial-of-service */
            centry_set_state(c, SERVICE_STATE_READY);
            s->nconnections++;
            s->ready_workers++;
            break;

        case SERVICE_STATE_UNKNOWN:
            s->nconnections++;
            centry_set_state(c, SERVICE_STATE_READY);
            syslog(LOG_ERR,
                   "service %s/%s pid %d in UNKNOWN state: serving one more multi-threaded connection, forced to READY state",
                   SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid);
            break;

        case SERVICE_STATE_DEAD:
            /* echoes from the past... do the accounting */
            s->nconnections++;
            break;

        default:
            /* Shouldn't get here */
            break;
        }
        break;

    default:
        syslog(LOG_CRIT, "service %s/%s pid %d: Software bug: unrecognized message 0x%x",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), c->pid, msg->message);
        break;
    }

    if (verbose)
        syslog(LOG_DEBUG, "service %s/%s now has %d ready workers",
               SERVICEPARAM(s->name), SERVICEPARAM(s->familyname), s->ready_workers);
}

static void add_start(const char *name, struct entry *e,
                      void *rock __attribute__((unused)))
{
    const char *cmd = masterconf_getstring(e, "cmd", "");
    strarray_t *tok;

    if (!strcmp(cmd,""))
        fatalf(EX_CONFIG, "unable to find command for %s", name);

    tok = strarray_split(cmd, NULL, 0);
    run_startup(name, tok);
    strarray_free(tok);
}

static void add_daemon(const char *name, struct entry *e, void *rock)
{
    int ignore_err = rock ? 1 : 0;
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", ""));
    rlim_t maxfds = (rlim_t) masterconf_getint(e, "maxfds", 256);
    int maxforkrate = masterconf_getint(e, "maxforkrate", 0);
    int reconfig = 0;
    int i;

    if (maxforkrate == 0) maxforkrate = 10; /* reasonable safety */

    if (!strcmp(cmd, "")) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "unable to find command or port for service '%s'", name);

        if (ignore_err) {
            syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
            goto done;
        }

        fatal(buf, EX_CONFIG);
    }

    /* see if we have an existing entry that can be reused */
    for (i = 0; i < nservices; i++) {
        /* skip non-primary instances */
        if (Services[i].associate > 0)
            continue;

        if (!strcmpsafe(Services[i].name, name) && Services[i].exec) {
            /* we have duplicate service names in the config file */
            char buf[256];
            snprintf(buf, sizeof(buf), "multiple entries for service '%s'", name);

            if (ignore_err) {
                syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
                goto done;
            }

            fatal(buf, EX_CONFIG);
        }

        /* must have empty/same service name, listen and proto */
        if (!Services[i].name || !strcmp(Services[i].name, name))
            break;
    }

    if (i == nservices) {
        /* we don't have an existing one, so create a new service */
        struct service *s = service_add(NULL);
        gettimeofday(&s->last_interval_start, 0);
    }
    else reconfig = 1;

    if (!Services[i].name) Services[i].name = xstrdup(name);

    strarray_free(Services[i].exec);
    Services[i].exec = strarray_split(cmd, NULL, 0);

    /* is this daemon actually there? */
    if (!verify_service_file(Services[i].exec)) {
        fatalf(EX_CONFIG,
                 "cannot find executable for daemon '%s'", name);
        /* if it is not, we're misconfigured, die. */
    }

    Services[i].maxforkrate = maxforkrate;
    Services[i].maxfds = maxfds;
    Services[i].babysit = 1;
    Services[i].max_workers = 1;
    Services[i].desired_workers = 1;
    Services[i].familyname = "daemon";

    if (verbose > 2)
        syslog(LOG_DEBUG, "%s: daemon '%s' (%s, %d)",
               reconfig ? "reconfig" : "add",
               Services[i].name, cmd,
               (int) Services[i].maxfds);

done:
    free(cmd);
    return;
}

static void add_service(const char *name, struct entry *e, void *rock)
{
    int ignore_err = rock ? 1 : 0;
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", ""));
    int prefork = masterconf_getint(e, "prefork", 0);
    int babysit = masterconf_getswitch(e, "babysit", 0);
    int maxforkrate = masterconf_getint(e, "maxforkrate", 0);
    char *listen = xstrdup(masterconf_getstring(e, "listen", ""));
    char *proto = xstrdup(masterconf_getstring(e, "proto", "tcp"));
    char *max = xstrdup(masterconf_getstring(e, "maxchild", "-1"));
    rlim_t maxfds = (rlim_t) masterconf_getint(e, "maxfds", 256);
    int reconfig = 0;
    int i, j;

    if(babysit && prefork == 0) prefork = 1;
    if(babysit && maxforkrate == 0) maxforkrate = 10; /* reasonable safety */

    if (!strcmp(cmd,"") || !strcmp(listen,"")) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "unable to find command or port for service '%s'", name);

        if (ignore_err) {
            syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
            goto done;
        }

        fatal(buf, EX_CONFIG);
    }

    /* see if we have an existing entry that can be reused */
    for (i = 0; i < nservices; i++) {
        /* skip non-primary instances */
        if (Services[i].associate > 0)
            continue;

        if (!strcmpsafe(Services[i].name, name) && Services[i].exec) {
            /* we have duplicate service names in the config file */
            char buf[256];
            snprintf(buf, sizeof(buf), "multiple entries for service '%s'", name);

            if (ignore_err) {
                syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
                goto done;
            }

            fatal(buf, EX_CONFIG);
        }

        /* must have empty/same service name, listen and proto */
        if ((!Services[i].name || !strcmp(Services[i].name, name)) &&
            (!Services[i].listen || !strcmp(Services[i].listen, listen)) &&
            (!Services[i].proto || !strcmp(Services[i].proto, proto)))
            break;
    }

    if (i == nservices) {
        /* either we don't have an existing entry or we are changing
         * the port parameters, so create a new service
         */
        struct service *s = service_add(NULL);
        gettimeofday(&s->last_interval_start, 0);
    }
    else if (Services[i].listen) reconfig = 1;

    if (!Services[i].name) Services[i].name = xstrdup(name);
    if (Services[i].listen) free(Services[i].listen);
    Services[i].listen = listen;
    listen = NULL; /* avoid freeing it */
    if (Services[i].proto) free(Services[i].proto);
    Services[i].proto = proto;
    proto = NULL; /* avoid freeing it */

    strarray_free(Services[i].exec);
    Services[i].exec = strarray_split(cmd, NULL, 0);

    /* is this service actually there? */
    if (!verify_service_file(Services[i].exec)) {
        fatalf(EX_CONFIG,
                 "cannot find executable for service '%s'", name);
        /* if it is not, we're misconfigured, die. */
    }

    Services[i].maxforkrate = maxforkrate;
    Services[i].maxfds = maxfds;

    if (!strcmp(Services[i].proto, "tcp") ||
        !strcmp(Services[i].proto, "tcp4") ||
        !strcmp(Services[i].proto, "tcp6")) {
        Services[i].desired_workers = prefork;
        Services[i].babysit = babysit;
        Services[i].max_workers = atoi(max);
        if (Services[i].max_workers < 0) {
            Services[i].max_workers = INT_MAX;
        }
    } else {
        /* udp */
        if (prefork > 1) prefork = 1;
        Services[i].desired_workers = prefork;
        Services[i].max_workers = 1;
    }

    if (reconfig) {
        /* reconfiguring an existing service, update any other instances */
        for (j = 0; j < nservices; j++) {
            if (Services[j].associate > 0 && Services[j].listen &&
                Services[j].name && !strcmp(Services[j].name, name)) {
                Services[j].maxforkrate = Services[i].maxforkrate;
                Services[j].exec = Services[i].exec;
                Services[j].desired_workers = Services[i].desired_workers;
                Services[j].babysit = Services[i].babysit;
                Services[j].max_workers = Services[i].max_workers;
            }
        }
    }

    if (verbose > 2)
        syslog(LOG_DEBUG, "%s: service '%s' (%s, %s:%s, %d, %d, %d)",
               reconfig ? "reconfig" : "add",
               Services[i].name, cmd,
               Services[i].proto, Services[i].listen,
               Services[i].desired_workers,
               Services[i].max_workers,
               (int) Services[i].maxfds);

done:
    free(cmd);
    free(listen);
    free(proto);
    free(max);
    return;
}

static void add_event(const char *name, struct entry *e, void *rock)
{
    int ignore_err = rock ? 1 : 0;
    /* Note: masterconf_getstring() shares a static buffer with
     * masterconf_getint() so we *must* strdup here */
    char *cmd = xstrdup(masterconf_getstring(e, "cmd", ""));
    int period = 60 * masterconf_getint(e, "period", 0);
    int at = masterconf_getint(e, "at", -1), hour, min;
    struct timeval now;
    struct event *evt;

    gettimeofday(&now, 0);

    if (!strcmp(cmd,"")) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "unable to find command or port for event '%s'", name);

        if (ignore_err) {
            syslog(LOG_WARNING, "WARNING: %s -- ignored", buf);
            free(cmd);
            return;
        }

        fatal(buf, EX_CONFIG);
    }

    evt = (struct event *) xzmalloc(sizeof(struct event));
    evt->name = xstrdup(name);

    if (at >= 0 && ((hour = at / 100) <= 23) && ((min = at % 100) <= 59)) {
        struct tm *tm = localtime(&now.tv_sec);

        period = 86400; /* 24 hours */
        evt->periodic = 0;
        evt->hour = hour;
        evt->min = min;
        tm->tm_hour = hour;
        tm->tm_min = min;
        tm->tm_sec = 0;
        evt->mark.tv_sec = mktime(tm);
        evt->mark.tv_usec = 0;
        if (timesub(&now, &evt->mark) < 0.0) {
            /* already missed it, so schedule for next day */
            evt->mark.tv_sec += period;
        }
    }
    else {
        evt->periodic = 1;
        evt->mark = now;
    }
    evt->period = period;

    evt->exec = strarray_splitm(cmd, NULL, 0);

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
static void limit_fds(rlim_t x)
{
    struct rlimit rl;

#ifdef HAVE_GETRLIMIT
    if (!getrlimit(RLIMIT_NUMFDS, &rl)) {
        if (x != RLIM_INFINITY && rl.rlim_max != RLIM_INFINITY && x > rl.rlim_max) {
            syslog(LOG_WARNING,
                   "limit_fds: requested %" PRIu64 ", but capped to %" PRIu64,
                   (uint64_t) x, (uint64_t) rl.rlim_max);
        }
        rl.rlim_cur = (x == RLIM_INFINITY || x > rl.rlim_max) ? rl.rlim_max : x;
    }
    else
#endif /* HAVE_GETRLIMIT */
    {
        rl.rlim_cur = rl.rlim_max = x;
    }

    if (verbose > 1) {
        syslog(LOG_DEBUG, "set maximum file descriptors to %ld/%ld",
               rl.rlim_cur, rl.rlim_max);
    }

    if (setrlimit(RLIMIT_NUMFDS, &rl) < 0) {
        syslog(LOG_ERR,
               "setrlimit: Unable to set file descriptors limit to %ld: %m",
               rl.rlim_cur);
    }
}
#else
static void limit_fds(rlim_t x)
{
}
#endif /* HAVE_SETRLIMIT */

static void reread_conf(struct timeval now)
{
    int i,j;
    struct event *ptr;
    struct centry *c;

    /* disable all services -
       they will be re-enabled if they appear in config file */
    for (i = 0; i < nservices; i++) service_forget_exec(&Services[i]);

    /* read services */
    masterconf_getsection("SERVICES", &add_service, (void*) 1);
    masterconf_getsection("DAEMON", &add_daemon, (void *)1);

    for (i = 0; i < nservices; i++) {
        /* Send SIGHUP to all children:
         *  - for services being added, there are still no children
         *  - for services being disabled, we need to terminate the children
         *  - otherwise (remaining services) we want to recycle children
         * Note that for services being disabled, it is important to first
         * signal them before shutting down their socket.
         */
        for (j = 0 ; j < child_table_size ; j++ ) {
            c = ctable[j];
            while (c != NULL) {
                if ((c->si == i) &&
                    (c->service_state != SERVICE_STATE_DEAD)) {
                    kill(c->pid, SIGHUP);
                    c->sighuptime = time(NULL);
                }
                c = c->next;
            }
        }

        if (!Services[i].exec && (Services[i].socket >= 0)) {
            /* cleanup newly disabled services */

            if (verbose > 2)
                syslog(LOG_DEBUG, "disable: service %s/%s socket %d pipe %d %d",
                       Services[i].name, Services[i].familyname,
                       Services[i].socket,
                       Services[i].stat[0], Services[i].stat[1]);

            /* Only free the service info on the primary */
            if(Services[i].associate == 0) {
                free(Services[i].listen);
                free(Services[i].proto);
            }
            Services[i].listen = NULL;
            Services[i].proto = NULL;
            Services[i].desired_workers = 0;

            /* close all listeners */
            shutdown(Services[i].socket, SHUT_RDWR);
            xclose(Services[i].socket);
        }
        else if (Services[i].exec && (Services[i].socket < 0)) {
            /* initialize new services */

            service_create(&Services[i]);
            if (verbose > 2)
                syslog(LOG_DEBUG, "init: service %s/%s socket %d pipe %d %d",
                       Services[i].name, Services[i].familyname,
                       Services[i].socket,
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
    init_janitor(now);

    /* send some feedback to admin */
    syslog(LOG_NOTICE,
            "Services reconfigured. %d out of %d (max %d) services structures are now in use",
            nservices, allocservices, SERVICE_MAX);
}

int main(int argc, char **argv)
{
    static const char lock_suffix[] = ".lock";

    const char *pidfile = MASTER_PIDFILE;
    char *pidfile_lock = NULL;

    int startup_pipe[2] = { -1, -1 };
    int pidlock_fd = -1;

    int i, opt, close_std = 1, daemon_mode = 0;
    const char *error_log = NULL;
    extern char *optarg;

    char *alt_config = NULL;

    int fd;
    fd_set rfds;
    char *p = NULL;
    int r = 0;

#ifdef HAVE_NETSNMP
    char *agentxsocket = NULL;
    int agentxpinginterval = -1;
#endif

    struct timeval now;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;
#ifdef HAVE_NETSNMP
    while ((opt = getopt(argc, argv, "C:L:M:p:l:Ddj:vVP:x:")) != EOF) {
#else
    while ((opt = getopt(argc, argv, "C:L:M:p:l:Ddj:vV")) != EOF) {
#endif
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
            daemon_mode = 1;
            break;
        case 'D':
            /* Debug Mode */
            close_std = 0;
            break;
        case 'L':
            /* error log */
            error_log = optarg;
            break;
        case 'j':
            /* Janitor frequency */
            janitor_frequency = atoi(optarg);
            if(janitor_frequency < 1)
                fatal("The janitor period must be at least 1 second", EX_CONFIG);
            break;
#ifdef HAVE_NETSNMP
        case 'P': /* snmp AgentXPingInterval */
            agentxpinginterval = atoi(optarg);
            break;
        case 'x': /* snmp AgentXSocket */
            agentxsocket = optarg;
            break;
#endif
        case 'v':
            verbose++;
            break;
        case 'V':
            /* print version information and exit */
            printf("%s %s\n", PACKAGE_NAME, CYRUS_VERSION);
            return 0;
        default:
            break;
        }
    }

    if (daemon_mode && !close_std)
        fatal("Unable to be both debug and daemon mode", EX_CONFIG);

    masterconf_init("master", alt_config);

    if (close_std || error_log) {
        /* close stdin/out/err */
        for (fd = 0; fd < 3; fd++) {
            const char *file = (error_log && fd > 0 ?
                                error_log : "/dev/null");
            int mode = (fd > 0 ? O_WRONLY : O_RDWR) |
                       (error_log && fd > 0 ? O_CREAT|O_APPEND : 0);
            close(fd);
            if (open(file, mode, 0666) != fd)
                fatalf(2, "couldn't open %s: %m", file);
        }
    }

    /* we reserve fds 3 and 4 for children to communicate with us, so they
       better be available. */
    for (fd = 3; fd < 5; fd++) {
        close(fd);
        if (dup(0) != fd) fatalf(2, "couldn't dup fd 0: %m");
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

        pidfile_lock = strconcat(pidfile, lock_suffix, (char *)NULL);

        pidlock_fd = open(pidfile_lock, O_CREAT|O_TRUNC|O_RDWR, 0644);
        if(pidlock_fd == -1) {
            syslog(LOG_ERR, "can't open pidfile lock: %s (%m)", pidfile_lock);
            exit(EX_OSERR);
        } else {
            if(lock_nonblocking(pidlock_fd, pidfile)) {
                syslog(LOG_ERR, "can't get exclusive lock on %s",
                       pidfile_lock);
                exit(EX_TEMPFAIL);
            }
        }

        if(pipe(startup_pipe) == -1) {
            syslog(LOG_ERR, "can't create startup pipe (%m)");
            exit(EX_OSERR);
        }

        /* Set the current working directory where cores can go to die. */
        const char *path = config_getstring(IMAPOPT_CONFIGDIRECTORY);
        if (path == NULL) {
                path = getenv("TMPDIR");
                if (path == NULL)
                        path = "/tmp";
        }
        (void) chdir(path);
        (void) chdir("cores");

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
            if (write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
                syslog(LOG_ERR, "can't write to startup parent pipe: %m");
            }

            fatal("setsid failure", EX_OSERR);
        }
    }

    limit_fds(1024);

    /* Write out the pidfile */
    pidfd = open(pidfile, O_CREAT|O_RDWR, 0644);
    if(pidfd == -1) {
        int exit_result = EX_OSERR;

        syslog(LOG_ERR, "can't open pidfile: %m");

        /* Tell our parent that we failed. */
        if (daemon_mode && write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
            syslog(LOG_ERR, "can't write to startup parent pipe: %m");
        }

        exit(EX_OSERR);
    } else {
        char buf[100];

        if(lock_nonblocking(pidfd, pidfile)) {
            int exit_result = EX_OSERR;

            /* Tell our parent that we failed. */
            if (write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
                syslog(LOG_ERR, "can't write to startup parent pipe: %m");
            }

            fatal("cannot get exclusive lock on pidfile (is another master still running?)", EX_OSERR);
        } else {
            int pidfd_flags = fcntl(pidfd, F_GETFD, 0);
            if (pidfd_flags != -1)
                pidfd_flags = fcntl(pidfd, F_SETFD,
                                    pidfd_flags | FD_CLOEXEC);
            if (pidfd_flags == -1) {
                int exit_result = EX_OSERR;

                syslog(LOG_ERR, "unable to set close-on-exec for pidfile: %m");

                /* Tell our parent that we failed. */
                if (write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
                    syslog(LOG_ERR, "can't write to startup parent pipe: %m");
                }

                fatalf(EX_OSERR, "unable to set close-on-exec for pidfile (see syslog for details)");
            }

            /* Write PID */
            snprintf(buf, sizeof(buf), "%lu\n", (unsigned long int)getpid());
            if(lseek(pidfd, 0, SEEK_SET) == -1 ||
               ftruncate(pidfd, 0) == -1 ||
               write(pidfd, buf, strlen(buf)) == -1) {
                int exit_result = EX_OSERR;

                syslog(LOG_ERR, "unable to write to pidfile: %m");

                /* Tell our parent that we failed. */
                if (daemon_mode && write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1) {
                    syslog(LOG_ERR, "can't write to startup parent pipe: %m");
                }

                fatalf(EX_OSERR, "unable to write to pidfile (see syslog for details)");
            }
            if (fsync(pidfd))
                fatalf(EX_OSERR, "unable to sync pidfile: %m");
        }
    }

    if(daemon_mode) {
        int exit_result = 0;

        /* success! */
        if (write(startup_pipe[1], &exit_result, sizeof(exit_result)) == -1)
            fatalf(EX_OSERR,
                   "could not write success result to startup pipe (%m)");

        close(startup_pipe[1]);
        xclose(pidlock_fd);
    }

    syslog(LOG_DEBUG, "process started");

#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
    /* initialize SNMP agent */

    /* make us a agentx client. */
#ifdef HAVE_NETSNMP
    netsnmp_enable_subagent();

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_ALARM_DONT_USE_SIG, 1);
    if (agentxpinginterval >= 0)
        netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, agentxpinginterval);

    if (agentxsocket != NULL)
        netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                              NETSNMP_DS_AGENT_X_SOCKET, agentxsocket);
#else
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, 1);
#endif

    /* initialize the agent library */
    init_agent("cyrusMaster");

    init_cyrusMasterMIB();

    init_snmp("cyrusMaster");
#endif

#if defined(__linux__) && defined(HAVE_LIBCAP)
    if (become_cyrus(/*is_master*/1) != 0) {
        syslog(LOG_ERR, "can't change to the cyrus user: %m");
        exit(1);
    }
#endif

    masterconf_getsection("START", &add_start, NULL);
    masterconf_getsection("SERVICES", &add_service, NULL);
    masterconf_getsection("EVENTS", &add_event, NULL);
    masterconf_getsection("DAEMON", &add_daemon, NULL);

    /* set signal handlers */
    sighandler_setup();

    /* initialize services */
    for (i = 0; i < nservices; i++) {
        service_create(&Services[i]);
        if (verbose > 2)
            syslog(LOG_DEBUG, "init: service %s/%s socket %d pipe %d %d",
                   Services[i].name, Services[i].familyname,
                   Services[i].socket,
                   Services[i].stat[0], Services[i].stat[1]);
    }

#if !defined(__linux__) || !defined(HAVE_LIBCAP)
    if (become_cyrus(/*is_master*/1) != 0) {
        syslog(LOG_ERR, "can't change to the cyrus user: %m");
        exit(1);
    }
#endif

    /* init ctable janitor */
    gettimeofday(&now, 0);
    init_janitor(now);

    /* ok, we're going to start spawning like mad now */
    syslog(LOG_DEBUG, "ready for work");

    for (;;) {
        int i, maxfd, ready_fds, total_children = 0;
        struct timeval tv, *tvptr;
        struct notify_message msg;
#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
        int blockp = 0;
#endif
        if (gotsigquit) {
            gotsigquit = 0;
            begin_shutdown();
        }

        /* run any scheduled processes */
        if (!in_shutdown)
            spawn_schedule(now);

        /* reap first, that way if we need to babysit we will */
        if (gotsigchld) {
            /* order matters here */
            gotsigchld = 0;
            reap_child();
        }

        /* do we have any services undermanned? */
        for (i = 0; i < nservices; i++) {
            total_children += Services[i].nactive;
            if (!in_shutdown) {
                if (Services[i].exec /* enabled */ &&
                    (Services[i].nactive < Services[i].max_workers) &&
                    (Services[i].ready_workers < Services[i].desired_workers))
                {
                    /* bring us up to desired_workers */
                    int j = Services[i].desired_workers - Services[i].ready_workers;

                    if (verbose) {
                        syslog(LOG_DEBUG, "service %s/%s needs %d more ready workers",
                            Services[i].name, Services[i].familyname, j);
                    }

                    while (j-- > 0) {
                        spawn_service(i);
                    }
                } else if (Services[i].exec
                          && Services[i].babysit
                          && Services[i].nactive == 0) {
                    syslog(LOG_ERR,
                          "lost all children for service: %s/%s.  " \
                          "Applying babysitter.",
                          Services[i].name, Services[i].familyname);
                    spawn_service(i);
                } else if (!Services[i].exec /* disabled */ &&
                          Services[i].name /* not yet removed */ &&
                          Services[i].nactive == 0) {
                    if (verbose > 2)
                        syslog(LOG_DEBUG, "remove: service %s/%s pipe %d %d",
                              Services[i].name, Services[i].familyname,
                              Services[i].stat[0], Services[i].stat[1]);

                    /* Only free the service info on the primary */
                    if (Services[i].associate == 0) {
                        free(Services[i].name);
                    }
                    Services[i].name = NULL;
                    Services[i].nforks = 0;
                    Services[i].nactive = 0;
                    Services[i].nconnections = 0;
                    Services[i].associate = 0;

                    xclose(Services[i].stat[0]);
                    xclose(Services[i].stat[1]);
                }
            }
        }

        if (in_shutdown && total_children == 0) {
           syslog(LOG_NOTICE, "All children have exited, closing down");
           exit(0);
        }

        if (gotsighup) {
            syslog(LOG_NOTICE, "got SIGHUP");
            gotsighup = 0;
            reread_conf(now);
        }

        FD_ZERO(&rfds);
        maxfd = 0;
        for (i = 0; i < nservices; i++) {
            int x = Services[i].stat[0];

            int y = Services[i].socket;

            /* messages */
            if (x >= 0) {
                if (verbose > 2)
                    syslog(LOG_DEBUG, "listening for messages from %s/%s",
                           Services[i].name, Services[i].familyname);
                FD_SET(x, &rfds);
            }
            if (x > maxfd) maxfd = x;

            /* connections */
            if (y >= 0 && Services[i].ready_workers == 0 &&
                Services[i].nactive < Services[i].max_workers &&
                !service_is_fork_limited(&Services[i])) {
                if (verbose > 2)
                    syslog(LOG_DEBUG, "listening for connections for %s/%s",
                           Services[i].name, Services[i].familyname);
                FD_SET(y, &rfds);
                if (y > maxfd) maxfd = y;
            }

            /* paranoia */
            if (Services[i].ready_workers < 0) {
                syslog(LOG_ERR, "%s/%s has %d workers?!?", Services[i].name,
                       Services[i].familyname, Services[i].ready_workers);
            }
        }
        maxfd++;                /* need 1 greater than maxfd */

        int interrupted = 0;
        do {
            /* how long to wait? - do now so that any scheduled wakeup
            * calls get accounted for*/
            gettimeofday(&now, 0);
            tvptr = NULL;
            if (schedule && !in_shutdown) {
                double delay = timesub(&now, &schedule->mark);
                if (!interrupted && delay > 0.0) {
                    timeval_set_double(&tv, delay);
                }
                else {
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;
                }
                tvptr = &tv;
            }

#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
            if (tvptr == NULL) blockp = 1;
            snmp_select_info(&maxfd, &rfds, tvptr, &blockp);
#endif
            errno = 0;
            ready_fds = myselect(maxfd, &rfds, NULL, NULL, tvptr);

            if (ready_fds < 0) {
                switch (errno) {
                case EAGAIN:
                case EINTR:
                    /* Try again to get valid rfds, this time without blocking so we
                     * will definitely process messages without getting interrupted
                     * again. */
                    interrupted++;
                    if (interrupted > 5) {
                        syslog(LOG_WARNING, "Repeatedly interrupted, too many signals?");
                        /* Fake a timeout */
                        r = 0;
                        FD_ZERO(&rfds);
                    }
                    break;
                default:
                    /* uh oh */
                    fatalf(1, "select failed: %m");
                }
            }
        } while (!in_shutdown && ready_fds < 0);

#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
        /* check for SNMP queries */
        if (ready_fds > 0)
            snmp_read(&rfds);
        if (ready_fds == 0)
            snmp_timeout();
#endif

        if (ready_fds > 0) {
            for (i = 0; i < nservices; i++) {
                int x = Services[i].stat[0];
                int y = Services[i].socket;

                if ((x >= 0) && FD_ISSET(x, &rfds)) {
                    while ((r = read_msg(x, &msg)) == 0)
                        process_msg(i, &msg);

                    if (r == 2) {
                        syslog(LOG_ERR,
                            "got incorrectly sized response from child: %x", i);
                        continue;
                    }
                    if (r < 0) {
                        syslog(LOG_ERR,
                            "error while receiving message from child %x: %m", i);
                        continue;
                    }
                }

                if (!in_shutdown && Services[i].exec &&
                    Services[i].nactive < Services[i].max_workers &&
                    Services[i].ready_workers == 0 &&
                    y >= 0 && FD_ISSET(y, &rfds))
                {
                    /* huh, someone wants to talk to us */
                    spawn_service(i);
                }
            }
        }

        gettimeofday(&now, 0);
        child_janitor(now);

#ifdef HAVE_NETSNMP
        if (ready_fds == 0)
            run_alarms();
#endif
    }

    /* never reached */
    return r;
}
