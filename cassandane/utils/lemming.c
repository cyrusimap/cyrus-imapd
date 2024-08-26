/*
 *  Copyright (c) 2011 Opera Software Australia Pty. Ltd.  All rights
 *  reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *  3. The name "Opera Software Australia" must not be used to
 *     endorse or promote products derived from this software without
 *     prior written permission. For permission or any legal
 *     details, please contact
 *      Opera Software Australia Pty. Ltd.
 *      Level 50, 120 Collins St
 *      Melbourne 3000
 *      Victoria
 *      Australia
 *
 *  4. Redistributions of any form whatsoever must retain the following
 *     acknowledgment:
 *     "This product includes software developed by Opera Software
 *     Australia Pty. Ltd."
 *
 *  OPERA SOFTWARE AUSTRALIA DISCLAIMS ALL WARRANTIES WITH REGARD TO
 *  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS, IN NO EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE
 *  FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 *  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 *  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/resource.h>

#define STATUS_FD   3
#define LISTEN_FD   4

#define MASTER_SERVICE_AVAILABLE        1
#define MASTER_SERVICE_UNAVAILABLE      2

static volatile int gotsighup = 0;

static void
usage(void)
{
    fprintf(stderr, "Usage: lemming [-d DELAY] [-m FAILMODE] [-t TAG]\n");
    fflush(stderr);
    exit(1);
}

static void no_cores(void)
{
    struct rlimit lim;
    int r;

    memset(&lim, 0, sizeof(lim));
    r = getrlimit(RLIMIT_CORE, &lim);
    if (lim.rlim_cur) {
        lim.rlim_cur = 0;
        r = setrlimit(RLIMIT_CORE, &lim);
        if (r)
            syslog(LOG_ERR, "setrlimit failed: %m");
    }
}

static void sighup_handler(int sig __attribute__((unused)))
{
    gotsighup = 1;
}

static void set_sighup_handler(int restartable)
{
    struct sigaction action;

    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESTART
    if (restartable) {
        action.sa_flags |= SA_RESTART;
    }
#endif
    action.sa_handler = sighup_handler;

    if (sigaction(SIGHUP, &action, NULL) < 0) {
        syslog(LOG_ERR, "unable to install signal handler for SIGHUP: %m");
        exit(1);
    }
}

static int
retry_write(int fd, const void *vbuf, int len)
{
    int n;
    const char *buf = vbuf;

    do
    {
        n = write(fd, buf, len);
        if (n < 0)
            return -1;
        if (n == 0)
            return -1;  /* WTF? */
        buf += n;
        len -= n;
    }
    while (len > 0);
    return 0;
}

static void
tell_master(int message)
{
    struct { int message; pid_t pid; } msg;

    memset(&msg, 0, sizeof(msg));
    msg.message = message;
    msg.pid = getpid();
    if (retry_write(STATUS_FD, &msg, sizeof(msg)) < 0)
    {
        syslog(LOG_ERR, "Couldn't write status message to master: %m");
        exit(1);
    }
}

static const char *
read_line_from_client(void)
{
    int fd;
    int n;
    int len = 0;
    uint32_t pid = getpid();
    static char line[128];
    static const int maxlen = sizeof(line)-1;

    syslog(LOG_ERR, "lemming serving");
    /* While 'accept'ing, let SIGHUP wake us up */
    set_sighup_handler(0);
    fd = accept(LISTEN_FD, NULL, NULL);
    set_sighup_handler(1);
    if (fd < 0)
    {
        if (gotsighup) {
            syslog(LOG_ERR, "lemming exiting normally on SIGHUP");
            exit(0);
        }
        syslog(LOG_ERR,  "cannot accept: %m");
        exit(1);
    }

    tell_master(MASTER_SERVICE_UNAVAILABLE);

    /* write out our pid, the Perl test code wants it */
    n = write(fd, &pid, sizeof(pid));
    if (n < 0)
    {
        syslog(LOG_ERR,  "cannot write pid: %m");
        exit(1);
    }
    if (n < (int)sizeof(pid))
    {
        syslog(LOG_ERR,  "short write of pid");
        exit(1);
    }

    /* read the command line from the Perl test code */
    for (;;)
    {
        n = read(fd, line+len, maxlen-len);
//      syslog(LOG_ERR, "read returned %d", n);
        if (n < 0)
        {
            syslog(LOG_ERR,  "cannot read command: %m");
            exit(1);
        }
        if (n == 0)
            break;      /* EOF */
        len += n;
        if (line[len-1] == '\r' ||
            line[len-1] == '\n')
            break;      /* have a whole line */
    }
    close(fd);
//     syslog(LOG_ERR, "read total of %d bytes", len);

    /* nul-terminate and trim the line */
    line[len] = '\0';
    while (len > 0 && isspace(line[len-1]))
        line[--len] = '\0';

    return line;
}

static void lemming_success(void)
{
    syslog(LOG_ERR, "lemming exiting normally");
    exit(0);
}

static void lemming_exit(void)
{
    syslog(LOG_ERR, "lemming exiting, code 1");
    exit(1);
}


int
main(int argc, char **argv)
{
    const char *mode = "success";
    const char *tag = "X";
    int c;
    int delay_ms = 20;
    char filename[256];
    socklen_t salen;
    struct sockaddr_storage localaddr;
    struct sockaddr *localsock = (struct sockaddr *)&localaddr;
    int family = AF_UNSPEC;

    /* don't interrupt me on SIGHUP */
    set_sighup_handler(1);
    no_cores();

    /* parse arguments */
    while ((c = getopt(argc, argv, "C:d:m:t:")) > 0)
    {
        switch (c)
        {
        case 'C':
            /* Cyrus alt-config option, ignored */
            break;
        case 'd':
            delay_ms = atoi(optarg);
            break;
        case 'm':
            mode = optarg;
            break;
        case 't':
            tag = optarg;
            break;
        default:
            usage();
        }
    }
    if (optind < argc)
        usage();

    openlog("lemming", LOG_PID, LOG_LOCAL6);

    snprintf(filename, sizeof(filename), "lemming.%s.%d", tag, (int)getpid());
    creat(filename, 0644);

    salen = sizeof(struct sockaddr_storage);
    if (!getsockname(LISTEN_FD, localsock, &salen)) {
        family = localsock->sa_family;
    }
    else {
        syslog(LOG_ERR, "unable to determine socket family: %m");
    }

    if (!strcmp(mode, "exit-ipv4/serve"))
    {
        switch (family) {
        case AF_INET:
            lemming_exit();
            break;

        default:
            mode = "serve";
            break;
        }
    }
    else if (!strcmp(mode, "exit-ipv6/serve"))
    {
        switch (family) {
        case AF_INET6:
            lemming_exit();
            break;

        default:
            mode = "serve";
            break;
        }
    }

    if (!strcmp(mode, "serve"))
        mode = read_line_from_client();
    else if (delay_ms)
        poll(NULL, 0, delay_ms);

    if (!strcmp(mode, "success"))
    {
        lemming_success();
    }
    else if (!strcmp(mode, "exit"))
    {
        lemming_exit();
    }
    else if (!strcmp(mode, "abort"))
    {
        syslog(LOG_ERR, "lemming abort()ing");
        abort();
    }
    else if (!strcmp(mode, "segv"))
    {
        syslog(LOG_ERR, "lemming receiving SEGV");
        *(char *)0 = 0;
    }
    else
    {
        syslog(LOG_ERR, "unknown failure mode \"%s\"", mode);
        fprintf(stderr, "lemming: unknown failure mode \"%s\"\n", mode);
        return 1;
    }

    return 0;
}
