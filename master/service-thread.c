/* service-thread.c -- skeleton for Cyrus service; calls the real main
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <signal.h>
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
#include "libconfig.h"
#include "xmalloc.h"
#include "strarray.h"
#include "signals.h"

extern int optind;
extern char *optarg;

/* number of times this service has been used */
static int use_count = 0;
static int verbose = 0;

static void notify_master(int fd, int msg)
{
    struct notify_message notifymsg;
    if (verbose) syslog(LOG_DEBUG, "telling master %x", msg);
    notifymsg.message = msg;
    notifymsg.service_pid = getpid();
    if (write(fd, &notifymsg, sizeof(notifymsg)) != sizeof(notifymsg)) {
        syslog(LOG_ERR, "unable to tell master %x: %m", msg);
    }
}

#ifdef HAVE_LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_DEBUG;
int deny_severity = LOG_ERR;

static void libwrap_init(struct request_info *req, char *service)
{
    request_init(req, RQ_DAEMON, service, 0);
}

static int libwrap_ask(struct request_info *req, int fd)
{
    struct sockaddr_storage sin_storage;
    struct sockaddr *sin = (struct sockaddr *)&sin_storage;
    socklen_t sinlen;
    int a;

    /* XXX: old FreeBSD didn't fill sockaddr correctly against AF_UNIX */
    sin->sa_family = AF_UNIX;

    /* is this a connection from the local host? */
    sinlen = sizeof(struct sockaddr_storage);
    if (getpeername(fd, sin, &sinlen) == 0) {
        if (sin->sa_family == AF_UNIX) {
            return 1;
        }
    }

    /* i hope using the sock_* functions are legal; it certainly makes
       this code very easy! */
    request_set(req, RQ_FILE, fd, 0);
    sock_host(req);

    a = hosts_access(req);
    if (!a) {
        syslog(deny_severity, "refused connection from %s", eval_client(req));
    }

    return a;
}

#else
struct request_info { int x; };

static void libwrap_init(struct request_info *r __attribute__((unused)),
                         char *service __attribute__((unused)))
{

}

static int libwrap_ask(struct request_info *r __attribute__((unused)),
                       int fd __attribute__((unused)))
{
    return 1;
}

#endif

extern void cyrus_init(const char *, const char *, unsigned, int);

int main(int argc, char **argv, char **envp)
{
    int fdflags;
    int fd;
    char *p = NULL, *service;
    struct request_info request;
    int opt;
    char *alt_config = NULL;
    int call_debugger = 0;

    extern const int config_need_data;

    /*
     * service_init and service_main need argv and argc, so they can process
     * service-specific options.  They need argv[0] to point into the real argv
     * memory space, so that setproctitle can work its magic.  But they also
     * need the generic options handled here to be removed, because they don't
     * know how to handle them.
     *
     * So, we create a strarray_t "service_argv", and populate it with the
     * options that we aren't handling here, using strarray_appendm (which
     * simply ptr-copies its argument), and pass that through, and everything
     * is happy.
     *
     * Note that we don't need to strarray_free service_argv, because it
     * doesn't contain any malloced memory.
     */
    strarray_t service_argv = STRARRAY_INITIALIZER;
    strarray_appendm(&service_argv, argv[0]);

    opterr = 0; /* disable error reporting,
                   since we don't know about service-specific options */
    while ((opt = getopt(argc, argv, "C:D")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'D':
            call_debugger = 1;
            break;
        default:
            strarray_appendm(&service_argv, argv[optind-1]);

            /* option has an argument */
            if (optind < argc && argv[optind][0] != '-')
                strarray_appendm(&service_argv, argv[optind++]);

            break;
        }
    }
    /* grab the remaining arguments */
    for (; optind < argc; optind++)
        strarray_appendm(&service_argv, argv[optind]);

    opterr = 1; /* enable error reporting */
    optind = 1; /* reset the option index for parsing by the service */

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
    service = xstrdup(p);

    cyrus_init(alt_config, service, 0, config_need_data);

    if (call_debugger) {
        char debugbuf[1024];
        int ret;
        const char *debugger = config_getstring(IMAPOPT_DEBUG_COMMAND);
        if (debugger) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"
            /* This is exactly the kind of usage that -Wformat is designed to
             * complain about (using user-supplied string as format argument),
             * but in this case the "user" is the server administrator, and
             * they're about to attach a debugger, so worrying about leaking
             * contents of memory here is a little silly! :)
             */
            snprintf(debugbuf, sizeof(debugbuf), debugger,
                     argv[0], getpid(), service);
#pragma GCC diagnostic pop
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
        if (MESSAGE_MASTER_ON_EXIT)
            notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
        return 1;
    }
    fdflags = fcntl(STATUS_FD, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(STATUS_FD, F_SETFD,
                                       fdflags | FD_CLOEXEC);
    if (fdflags == -1) {
        syslog(LOG_ERR, "unable to set close on exec: %m");
        if (MESSAGE_MASTER_ON_EXIT)
            notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
        return 1;
    }

    if (service_init(service_argv.count, service_argv.data, envp) != 0) {
        if (MESSAGE_MASTER_ON_EXIT)
            notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
        return 1;
    }

    for (;;) {
        /* ok, listen to this socket until someone talks to us */
        fd = -1;
        while (fd < 0) { /* loop until we succeed */
            fd = accept(LISTEN_FD, NULL, NULL);
            if (fd < 0) {
                switch (errno) {
                case EINTR:
        signals_poll();
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
                case ECONNABORTED:
                    break;
                default:
                    syslog(LOG_ERR, "accept failed: %m");
                    if (MESSAGE_MASTER_ON_EXIT)
                        notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                    service_abort(EX_OSERR);
                }
            }
        }

        libwrap_init(&request, getenv("CYRUS_SERVICE"));

        if (!libwrap_ask(&request, fd)) {
            /* connection denied! */
            shutdown(fd, SHUT_RDWR);
            close(fd);
            continue;
        }

        syslog(LOG_DEBUG, "accepted connection");

        use_count++;
        notify_master(STATUS_FD, MASTER_SERVICE_CONNECTION_MULTI);
        if (service_main_fd(fd, service_argv.count, service_argv.data, envp) < 0) {
            break;
        }
    }

    if (MESSAGE_MASTER_ON_EXIT)
        notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
    service_abort(0);
    return 0;
}
