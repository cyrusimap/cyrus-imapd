/*
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <errno.h>
#include "timeout.h"

static void (*timeout_callback)(void);
static pid_t timeout_pid = -1;
static int timeout_fd = -1;

#define PIPE_READ       0
#define PIPE_WRITE      1
#define CMD_BEGIN       'B'
#define CMD_END         'E'

static void sigusr1_handler(int sig __attribute__((unused)))
{
// fprintf(stderr, "timeout: received SIGUSR1\n");
    if (timeout_callback)
        timeout_callback();
}

static void timeout_mainloop(int fd, pid_t pid)
{
    struct pollfd pfd;
    char c;
    int r;
    int timeout = -1;

    for (;;) {
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;

// if (timeout < 0)
// fprintf(stderr, "timeout: waiting for command\n");
// else
// fprintf(stderr, "timeout: waiting for command or %d.%03d sec\n", timeout/1000, timeout % 1000);

        /* wait for command from the parent or timeout */
        r = poll(&pfd, 1, timeout);
// fprintf(stderr, "timeout: awoke, r=%d\n", r);
        if (r < 0) {
            perror("timeout: poll");
            exit(1);
        }
        if (r == 0) {
            /* timed out */
// fprintf(stderr, "timeout: sending USR1 to %d\n", (int)pid);
            kill(pid, SIGUSR1);
            timeout = -1;
            continue;
        }
        if (r != 1 || !pfd.revents) {
            /* WTF?? */
            fprintf(stderr, "timeout: weirdness from poll: "
                            "r=%d pfd.revents=%d\n",
                            r, pfd.revents);
            exit(1);
        }

        r = read(fd, &c, sizeof(c));
        if (r < 0) {
            perror("timeout: read");
            exit(1);
        }
        if (r == 0) {
            /* EOF: parent closed pipe */
            exit(0);
        }
        if (r != 1) {
            fprintf(stderr, "timeout: short read\n");
            exit(1);
        }

        switch (c) {
        case CMD_BEGIN:
            timeout = -1;
            r = read(fd, &timeout, sizeof(timeout));
            if (r < 0) {
                perror("timeout: read");
                exit(1);
            }
            if (r == 0) {
                /* EOF: parent closed pipe */
                exit(0);
            }
            if (r != sizeof(timeout)) {
                fprintf(stderr, "timeout: short read\n");
                exit(1);
            }
            break;

        case CMD_END:
            timeout = -1;
            break;

        default:
            fprintf(stderr, "timeout: Unknown command '%c' (%#x)\n",
                            c, (unsigned) c);
            exit(1);
        }
    }
}

int timeout_init(void (*cb)(void))
{
    int pipefd[2];
    pid_t pid;
    struct sigaction sa;
    int r;

    timeout_callback = cb;

    /* set up a pipe to communicate with the
     * timeout process */
    r = pipe(pipefd);
    if (r < 0) {
        perror("timeout: pipe");
        return -1;
    }

    /* fork the timeout process */
    pid = fork();
    if (pid < 0) {
        perror("timeout: fork");
        return -1;
    }
    if (pid) {
        /* parent */
        timeout_pid = pid;
        timeout_fd = dup2(pipefd[PIPE_WRITE], 253);
        if (timeout_fd < 0) {
            perror("timeout: dup2");
            return -1;
        }
        close(pipefd[PIPE_READ]);
        close(pipefd[PIPE_WRITE]);

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sigusr1_handler;
        sa.sa_flags = SA_NODEFER;
        sigaction(SIGUSR1, &sa, NULL);
    } else {
        /* child */
        close(pipefd[PIPE_WRITE]);
        timeout_mainloop(pipefd[PIPE_READ], getppid());
        exit(0);
    }

    return 0;
}

int timeout_begin(int millisec)
{
    char c;
    int r;

// fprintf(stderr, "timeout_begin\n");
    if (timeout_fd < 0)
        return -1;

    c = CMD_BEGIN;
    r = write(timeout_fd, &c, sizeof(c));
    if (r < 0) {
        perror("timeout: write");
        return -1;
    }
    r = write(timeout_fd, &millisec, sizeof(millisec));
    if (r < 0) {
        perror("timeout: write");
        return -1;
    }
    return 0;
}

int timeout_end(void)
{
    char c;
    int r;

// fprintf(stderr, "timeout_end\n");
    if (timeout_fd < 0)
        return -1;

    c = CMD_END;
    r = write(timeout_fd, &c, sizeof(c));
    if (r < 0) {
        perror("timeout: write");
        return -1;
    }
    return 0;
}

void timeout_fini(void)
{
    int r;
    int status;

    if (timeout_fd >= 0) {
        close(timeout_fd);
        timeout_fd = -1;
    }

    if (timeout_pid > 0) {
        r = kill(timeout_pid, SIGTERM);
        if (r < 0 && errno != ESRCH)
            perror("timeout: kill");
        else
            waitpid(timeout_pid, &status, 0);
        timeout_pid = -1;
    }

    signal(SIGUSR1, SIG_IGN);
}

