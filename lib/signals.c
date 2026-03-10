/* signals.c - signal handling functions to allow clean shutdown */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "assert.h"
#include "libconfig.h"
#include "signals.h"
#include "xmalloc.h"
#include "util.h"

#ifndef _NSIG
#define _NSIG 65
#endif
static volatile sig_atomic_t gotsignal[_NSIG];
static volatile pid_t killer_pid;

static void sighandler(int sig, siginfo_t *si,
                       void *ucontext __attribute__((unused)))
{
    if (sig < 1 || sig >= _NSIG)
        sig = _NSIG-1;
    gotsignal[sig] = 1;

    /* remember a process that sent us a fatal signal */
    if ((sig == SIGINT || sig == SIGQUIT || sig == SIGTERM) &&
        si &&
        si->si_code == SI_USER)
        killer_pid = si->si_pid;
}

EXPORTED void signals_add_handlers(int alarm)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESETHAND
    action.sa_flags |= SA_RESETHAND;
#endif

    action.sa_sigaction = sighandler;
    action.sa_flags |= SA_SIGINFO;

    /* SIGALRM used as a syscall timeout, so we don't set SA_RESTART */
    if (alarm && sigaction(SIGALRM, &action, NULL) < 0) {
        fatal("unable to install signal handler for SIGALRM", EX_TEMPFAIL);
    }

    /* no restartable SIGQUIT thanks */
    if (sigaction(SIGQUIT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGQUIT", EX_TEMPFAIL);
    if (sigaction(SIGINT, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGINT", EX_TEMPFAIL);
    if (sigaction(SIGTERM, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGTERM", EX_TEMPFAIL);

    /* don't reset SIGUSR1 handler on signal */
#ifdef SA_RESETHAND
    action.sa_flags &= ~SA_RESETHAND;
#endif
    if (sigaction(SIGUSR1, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGUSR1", EX_TEMPFAIL);

    signals_reset_sighup_handler(1);
}

EXPORTED void signals_reset_sighup_handler(int restartable)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESTART
    if (restartable) {
        action.sa_flags |= SA_RESTART;
    }
#endif
    action.sa_sigaction = sighandler;
    action.sa_flags |= SA_SIGINFO;

    if (sigaction(SIGHUP, &action, NULL) < 0)
        fatal("unable to install signal handler for SIGHUP", EX_TEMPFAIL);
}

static shutdownfn *shutdown_cb = NULL;
static int signals_in_shutdown = 0;

EXPORTED void signals_set_shutdown(shutdownfn *s)
{
    shutdown_cb = s;
}

/* Build a human-readable description of another process from just the
 * process id.  On some platforms this is enough to tell us something
 * useful about the other process. Returns a new string which must be
 * free()d by the caller. */
static char *describe_process(pid_t pid)
{
#if defined(__linux__)
    int i;
    int fd;
    int n;
    char buf[1024+32];
    char cmdline[1024];

    snprintf(buf, sizeof(buf), "/proc/%d/cmdline", (int)pid);
    cmdline[0] = '\0';
    fd = open(buf, O_RDONLY, 0);
    if (fd >= 0) {
        n = read(fd, cmdline, sizeof(cmdline)-1);
        if (n > 0) {
            if (!cmdline[n-1])
                n--;        /* ignore trailing nul */
            for (i = 0 ; i < n ; i++) {
                if (cmdline[i] == '\0')
                    cmdline[i] = ' ';
            }
            cmdline[n] = '\0';
        }
        close(fd);
    }
    if (!cmdline[0])
        strcpy(cmdline, "unknown");
    snprintf(buf, sizeof(buf), "%d (%s)", (int)pid, cmdline);
    return xstrdup(buf);
#else
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", (int)pid);
    return xstrdup(buf);
#endif
}

static int signals_poll_mask(sigset_t *oldmaskp)
{
    int sig;

    if (!signals_in_shutdown &&
        (gotsignal[SIGINT] || gotsignal[SIGQUIT] || gotsignal[SIGTERM])) {

        if (killer_pid && killer_pid != getppid()) {
            /* whine in syslog if we were sent a graceful shutdown signal
             * by anyone other than the master process.  */
            char *desc = describe_process(killer_pid);
            syslog(LOG_NOTICE, "graceful shutdown initiated by "
                               "unexpected process %s", desc);
            free(desc);
        }
        else {
            syslog(LOG_NOTICE, "graceful shutdown");
        }

        if (oldmaskp)
            sigprocmask(SIG_SETMASK, oldmaskp, NULL);
        if (shutdown_cb) {
            signals_in_shutdown = 1;
            shutdown_cb(EX_TEMPFAIL);
        }
        else exit(EX_TEMPFAIL);
    }
    for (sig = 1 ; sig < _NSIG ; sig++) {
        switch (sig) {
        case SIGUSR1:
            if (gotsignal[sig]) {
                gotsignal[sig] = 0;
                config_toggle_debug();
            }
            break;
        default:
            if (gotsignal[sig]) return sig;
            break;
        }
    }
    return 0;
}

EXPORTED int signals_poll(void)
{
    return signals_poll_mask(NULL);
}

/*
 * Same interface as select() but closes the race between
 * select() blocking and delivery of some signficant signals
 * like SIGTERM.  This is necessary to ensure clean shutdown
 * of Cyrus processes.
 */
EXPORTED int signals_select(int nfds, fd_set *rfds, fd_set *wfds,
                            fd_set *efds, struct timeval *tout)
{
    if (nfds > 0.9 * FD_SETSIZE) {
        syslog(LOG_WARNING, "signals_select: nfds = %d/%d", nfds, FD_SETSIZE);
        assert(nfds < FD_SETSIZE);
    }

#if HAVE_PSELECT
    /* pselect() closes the race between SIGCHLD arriving
    * and select() sleeping for up to 10 seconds. */
    struct timespec ts, *tsptr = NULL;
    sigset_t blocked;
    sigset_t oldmask;
    int saved_errno;
    int r;

    /* temporarily block all the signals we want
     * to be caught reliably */
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    sigaddset(&blocked, SIGALRM);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    sigprocmask(SIG_BLOCK, &blocked, &oldmask);

    /* Those signals will not arrive now.  Check to see if any
     * of them arrived before we blocked them */
    signals_poll_mask(&oldmask);

    if (tout) {
        ts.tv_sec = tout->tv_sec;
        ts.tv_nsec = tout->tv_usec * 1000;
        tsptr = &ts;
    }

    /* pselect() allows the restartable signals to arrive */
    r = pselect(nfds, rfds, wfds, efds, tsptr, &oldmask);

    if (r < 0 && (errno == EAGAIN || errno == EINTR))
        signals_poll_mask(&oldmask);

    /* restore the old signal mask */
    saved_errno = errno;
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
    errno = saved_errno;

    return r;
#else
    int r;

    r = select(nfds, rfds, wfds, efds, tout);
    if (r < 0 && (errno == EAGAIN || errno == EINTR))
        signals_poll();

    return r;
#endif
}

EXPORTED void signals_clear(int sig)
{
    if (sig >= 0 && sig < _NSIG)
        gotsignal[sig] = 0;
}
