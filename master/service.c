/* service.c - skeleton for Cyrus service; calls the real main */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <limits.h>

#include "service.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "strarray.h"
#include "signals.h"
#include "util.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern int optind, opterr;
extern char *optarg;

/* number of times this service has been used */
static int use_count = 0;
static int verbose = 0;
static int lockfd = -1;
static int newfile = 0;

/* proto="quic" only: see service.h. Populated by quic_recv_handoff()
 * just before service_main() runs, for imap/quic.c to read from
 * inside it. */
struct quic_handoff quic_handoff;

void notify_master(int fd, int msg)
{
    struct notify_message notifymsg;
    if (verbose) syslog(LOG_DEBUG, "telling master %x", msg);
    notifymsg.message = msg;
    notifymsg.service_pid = getpid();
    if (write(fd, &notifymsg, sizeof(notifymsg)) != sizeof(notifymsg)) {
        syslog(LOG_ERR, "unable to tell master %x: %m", msg);
    }
}

/* proto="quic" only: receive one handoff message from master on
 * fd (see service.h's QUIC_HANDOFF_FD) -- the connection's own
 * socket via SCM_RIGHTS ancillary data, and its struct quic_handoff
 * payload into *out. Returns the received socket fd on success, or
 * -1 (errno set; EBADMSG for a malformed message, i.e. one master
 * itself would never actually send) on failure. */
static int quic_recv_handoff(int fd, struct quic_handoff *out)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align; /* for alignment only, never referenced */
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    ssize_t n;
    int sock = -1;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = out;
    iov.iov_len = sizeof(*out);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    n = recvmsg(fd, &msg, 0);
    if (n != (ssize_t) sizeof(*out)) {
        if (n >= 0) errno = EBADMSG;
        return -1;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&sock, CMSG_DATA(cmsg), sizeof(sock));
            break;
        }
    }

    if (sock < 0) {
        errno = EBADMSG;
        return -1;
    }

    return sock;
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

static int getlockfd(char *service, int id)
{
    char lockfile[1024];
    int fd;

    snprintf(lockfile, sizeof(lockfile), "%s/socket/%s-%d.lock",
             config_dir, service, id);
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
               !signals_poll())
            /* noop */;

        if (rc < 0 && signals_poll()) {
            if (MESSAGE_MASTER_ON_EXIT)
                notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
            service_abort(0);
            return -1;
        }

        if (rc < 0) {
            syslog(LOG_ERR, "fcntl: F_SETLKW: error getting accept lock: %m");
            if (MESSAGE_MASTER_ON_EXIT)
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
               errno == EINTR && !signals_poll())
            /* noop */;

        if (rc < 0) {
            syslog(LOG_ERR,
                   "fcntl: F_SETLKW: error releasing accept lock: %m");
            if (MESSAGE_MASTER_ON_EXIT)
                notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
            service_abort(EX_OSERR);
            return -1;
        }
    }

    return 0;
}

static int safe_wait_readable(int fd)
{
    fd_set rfds;
    int r;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    /* Waiting for incoming connection, we want to leave as soon as
     * possible upon SIGHUP. Julien explains:
     *
     * The thing is SIGHUP handler is set as restartable, which is a good thing
     * when we have received a connection and are processing client commands:
     * we don't want to be interrupted by that signal.
     *
     * On the other hand, when we are waiting to receive a new connection, I
     * needed a way to make the service instance holding the lock react faster.
     * Without resetting SIGHUP as not restartable, the instance would just
     * keep on waiting for a new connection (while the other instances -
     * waiting for the lock - had received and processed the signal right
     * away).
     *
     * Now that we have safe_wait_readable, Linux systems already react faster
     * because there select/pselect always returns -1/EINTR even if SA_RESTART
     * is set. But that may not be the case in other OSes (POSIX spec says it
     * is implementation-defined whether it does restart or return -1/EINTR
     * when SA_RESTART is set).
     */
    signals_reset_sighup_handler(0);

    r = signals_select(fd+1, &rfds, NULL, NULL, NULL);

    /* we don't want to be interrupted by SIGHUP anymore */
    signals_reset_sighup_handler(1);

    return r;
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
    int debug_stdio = 0;
    int max_use = MAX_USE;
    int reuse_timeout = REUSE_TIMEOUT;
    int soctype = 0;
    socklen_t typelen = sizeof(soctype);
    int is_quic = 0;
    struct sockaddr socname;
    socklen_t addrlen = sizeof(struct sockaddr);
    int id;
    char path[PATH_MAX];
    struct stat sbuf;
    ino_t start_ino;
    off_t start_size;
    time_t start_mtime;

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
    while ((opt = getopt(argc, argv, "C:U:T:DX")) != EOF) {
        if (argv[optind-1][0] == '-' && strlen(argv[optind-1]) > 2) {
            /* we have merged options */
            syslog(LOG_ERR,
                   "options and arguments MUST be separated by whitespace");
            exit(EX_USAGE);
        }

        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'U': /* maximum uses */
            max_use = atoi(optarg);
            if (max_use < 0) max_use = 0;
            break;
        case 'T': /* reuse timeout */
            reuse_timeout = atoi(optarg);
            if (reuse_timeout < 0) reuse_timeout = 0;
            break;
        case 'D':
            call_debugger = 1;
            break;
        case 'X':
            debug_stdio = 1;
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

    p = getenv("CYRUS_ID");
    if (p == NULL) {
        syslog(LOG_ERR, "could not getenv(CYRUS_ID); exiting");
        exit(EX_SOFTWARE);
    }
    id = atoi(p);

    /* proto="quic" services don't use LISTEN_FD at all -- master
     * hands each one exactly one connection at a time via
     * QUIC_HANDOFF_FD (see service.h) -- see the is_quic branches
     * below. */
    p = getenv("CYRUS_SERVICE_PROTO");
    is_quic = (p != NULL && !strcmp(p, "quic"));

    /* if timeout is enabled, pick a random timeout between reuse_timeout
     * and 2*reuse_timeout to avoid massive IO overload if the network
     * connection goes away */
    if (reuse_timeout)
        reuse_timeout = reuse_timeout + (rand() % reuse_timeout);

    extern const int config_need_data;
    cyrus_init(alt_config, service, 0, config_need_data);

    if (call_debugger) {
        char debugbuf[1024];
        int ret;
        const char *debugger = config_getstring(IMAPOPT_DEBUG_COMMAND);
        if (debugger) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
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

    if (debug_stdio) {
        if (service_init(service_argv.count, service_argv.data, envp) != 0) {
            return 1;
        }
    }
    else {
        /* set close on exec */
        if (is_quic) {
            /* No raw listening socket for quic workers -- each
             * connection arrives individually via QUIC_HANDOFF_FD
             * (see service.h), not something to accept()/recvfrom()
             * peek on the way LISTEN_FD is below. Treat it as
             * UDP-shaped for the soctype-gated code further down
             * (no libwrap/keepalive concept applies to it either). */
            fdflags = fcntl(QUIC_HANDOFF_FD, F_GETFD, 0);
            if (fdflags != -1) fdflags = fcntl(QUIC_HANDOFF_FD, F_SETFD,
                                            fdflags | FD_CLOEXEC);
            if (fdflags == -1) {
                xsyslog_ev(LOG_ERR, "service.quic_handoff.cloexec_failed");
                if (MESSAGE_MASTER_ON_EXIT)
                    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                return 1;
            }
            soctype = SOCK_DGRAM;
        }
        else {
            fdflags = fcntl(LISTEN_FD, F_GETFD, 0);
            if (fdflags != -1) fdflags = fcntl(LISTEN_FD, F_SETFD,
                                            fdflags | FD_CLOEXEC);
            if (fdflags == -1) {
                xsyslog_ev(LOG_ERR, "service.listen.cloexec_failed");
                if (MESSAGE_MASTER_ON_EXIT)
                    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                return 1;
            }

            /* figure out what sort of socket this is */
            if (getsockopt(LISTEN_FD, SOL_SOCKET, SO_TYPE,
                        (char *) &soctype, &typelen) < 0) {
                xsyslog_ev(LOG_ERR, "service.listen.socktype_failed");
                if (MESSAGE_MASTER_ON_EXIT)
                    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                return 1;
            }
            if (getsockname(LISTEN_FD, &socname, &addrlen) < 0) {
                xsyslog_ev(LOG_ERR, "service.listen.sockname_failed");
                if (MESSAGE_MASTER_ON_EXIT)
                    notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                return 1;
            }
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
    }

    /* determine initial process file inode, size and mtime */
    if (service_argv.data[0][0] == '/')
        strlcpy(path, service_argv.data[0], sizeof(path));
    else
        snprintf(path, sizeof(path), "%s/%s", LIBEXEC_DIR, service_argv.data[0]);

    stat(path, &sbuf);
    start_ino= sbuf.st_ino;
    start_size = sbuf.st_size;
    start_mtime = sbuf.st_mtime;

    getlockfd(service, id);

    if (debug_stdio) {
        service_main(service_argv.count, service_argv.data, envp);
        service_abort(0);
        return 0;
    }

    for (;;) {
        /* ok, listen to this socket until someone talks to us */

        /* (re)set signal handlers, including SIGALRM */
        signals_add_handlers(SIGALRM);

        if (use_count > 0) {
            /* we want to time out after 60 seconds, set an alarm */
            alarm(reuse_timeout);
        }

        if (is_quic) {
            /* Every trip through this loop (fresh prefork, or just
             * finished a connection) is about to block waiting on
             * QUIC_HANDOFF_FD -- tell master so it can add us to the
             * idle pool. Unlike TCP/UDP, quic workers get no
             * optimistic ready_workers++ at fork time (see
             * quic_dispatch_connection() for why), so without this a
             * prefork'd worker would sit here forever, alive but
             * invisible to dispatch. */
            notify_master(STATUS_FD, MASTER_SERVICE_QUIC_IDLE);
        }
        else {
            /* lock -- pointless for quic: QUIC_HANDOFF_FD is private
             * to this one worker, so there's no shared accept() race
             * with sibling workers to serialize against the way there
             * is for a shared LISTEN_FD. */
            lockaccept();
        }

        fd = -1;
        while (fd < 0 && !signals_poll()) { /* loop until we succeed */
            /* check current process file inode, size and mtime */
            int r = stat(path, &sbuf);
            if (r < 0) {
                /* This might happen transiently during a package
                 * upgrade or permanently after package removal.
                 * In either case, it's time to die. */
                syslog(LOG_INFO, "cannot stat process file: %m");
                break;
            }
            if (sbuf.st_ino != start_ino || sbuf.st_size != start_size ||
                sbuf.st_mtime != start_mtime) {
                syslog(LOG_INFO, "process file has changed");
                newfile = 1;
                break;
            }

            if (is_quic) {
                /* Wait signal-safely, same rationale as the SOCK_STREAM
                 * and udp cases below. */
                if (safe_wait_readable(QUIC_HANDOFF_FD) < 0)
                    continue;
                fd = quic_recv_handoff(QUIC_HANDOFF_FD, &quic_handoff);
                if (fd < 0) {
                    switch (errno) {
                    case EINTR:
                        signals_poll();
                        GCC_FALLTHROUGH
                    case EAGAIN:
                        break;

                    default:
                        xsyslog_ev(LOG_ERR,
                                  "service.quic_handoff.recv_failed");
                        if (MESSAGE_MASTER_ON_EXIT)
                            notify_master(STATUS_FD,
                                         MASTER_SERVICE_UNAVAILABLE);
                        service_abort(EX_OSERR);
                    }
                }
            }
            else if (soctype == SOCK_STREAM) {
                /* Wait for the file descriptor to be connected to, in a
                 * signal-safe manner.  This ensures the accept() does
                 * not block and we don't need to make it signal-safe.  */
                if (safe_wait_readable(LISTEN_FD) < 0)
                    continue;
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
                    case ECONNABORTED:
                    case EAGAIN:
                        break;

                    case EINVAL:
                        if (signals_poll() == SIGHUP) break;
                        GCC_FALLTHROUGH

                    default:
                        syslog(LOG_ERR, "accept failed: %m");
                        if (MESSAGE_MASTER_ON_EXIT)
                            notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                        service_abort(EX_OSERR);
                    }
                }
            } else {
                /* udp */
                struct sockaddr_storage from;
                socklen_t fromlen;
                char ch;
                int r;

                if (safe_wait_readable(LISTEN_FD) < 0)
                    continue;
                fromlen = sizeof(from);
                r = recvfrom(LISTEN_FD, (void *) &ch, 1, MSG_PEEK,
                             (struct sockaddr *) &from, &fromlen);
                if (r == -1) {
                    if (signals_poll() == SIGHUP) break;
                    syslog(LOG_ERR, "recvfrom failed: %m");
                    if (MESSAGE_MASTER_ON_EXIT)
                        notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
                    service_abort(EX_OSERR);
                }
                fd = LISTEN_FD;
            }
        }

        /* unlock */
        if (!is_quic) unlockaccept();

        if (fd < 0 && (signals_poll() || newfile)) {
            /* timed out (SIGALRM), SIGHUP, or new process file */
            if (MESSAGE_MASTER_ON_EXIT)
                notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
            service_abort(0);
        }
        if (fd < 0) {
            /* how did this happen? - we might have caught a signal. */
            syslog(LOG_ERR, "accept() failed but we didn't catch it?");
            if (MESSAGE_MASTER_ON_EXIT)
                notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
            service_abort(EX_SOFTWARE);
        }

        /* cancel the alarm */
        alarm(0);

        /* tcp only */
        if(soctype == SOCK_STREAM && socname.sa_family != AF_UNIX) {
            libwrap_init(&request, service);

            if (!libwrap_ask(&request, fd)) {
                /* connection denied! */
                shutdown(fd, SHUT_RDWR);
                close(fd);
                continue;
            }

            tcp_enable_keepalive(fd);
        }

        notify_master(STATUS_FD, MASTER_SERVICE_UNAVAILABLE);
        syslog(LOG_DEBUG, "accepted connection");

        if (fd != STDIN_FILENO && dup2(fd, STDIN_FILENO) < 0) {
            syslog(LOG_ERR, "can't duplicate accepted socket: %m");
            service_abort(EX_OSERR);
        }
        if (fd != STDOUT_FILENO && dup2(fd, STDOUT_FILENO) < 0) {
            syslog(LOG_ERR, "can't duplicate accepted socket: %m");
            service_abort(EX_OSERR);
        }
#if 0  /* XXX  This appears to have no valid use (and breaks wire protocols).
          We should look into capturing stderr and sending it to syslog. */
        if (fd != STDERR_FILENO && dup2(fd, STDERR_FILENO) < 0) {
            syslog(LOG_ERR, "can't duplicate accepted socket: %m");
            service_abort(EX_OSERR);
        }
#endif

        /* tcp only, plus quic (its received fd is a plain socket, not
         * something aliased onto a well-known fd number the way
         * LISTEN_FD is) -- closing our extra reference to it here
         * matters more now that a worker may live to receive many
         * connections, not just one. */
        if (soctype == SOCK_STREAM || is_quic) {
            if (fd > STDERR_FILENO) close(fd);
        }

        notify_master(STATUS_FD, MASTER_SERVICE_CONNECTION);
        use_count++;
        service_main(service_argv.count, service_argv.data, envp);
        /* Returning here just means this one QUIC connection ended,
         * not that the process is used up -- looping back to wait on
         * QUIC_HANDOFF_FD again is the same shape as accept()ing again
         * below for TCP, including reuse_timeout/max_use via the same
         * signals_poll()/use_count check. */
        if (signals_poll() || use_count >= max_use) {
            /* caught SIGHUP or exceeded max use count */
            break;
        }

        /* quic's equivalent (MASTER_SERVICE_QUIC_IDLE) is sent at the
         * top of the loop instead, right before we'd otherwise wait
         * on QUIC_HANDOFF_FD -- see the comment there for why it
         * can't wait until after service_main() the way this one
         * does (a prefork'd worker's very first iteration never gets
         * here at all until it's already served a connection). */
        if (!is_quic) notify_master(STATUS_FD, MASTER_SERVICE_AVAILABLE);
    }

    service_abort(0);
    return 0;
}
