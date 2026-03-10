/* gdbtramp.c - a small trampoline program to help run gdb at the right time */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>
#include <signal.h>
#include <sys/poll.h>

#ifndef __GNUC__
#define __attribute__(x)
#endif

static const char *basename(const char *path)
{
    const char *t = strrchr(path, '/');
    return (t ? ++t : path);
}

static volatile int got_sigusr1 = 0;

static void
handle_sigusr1(int sig __attribute__((unused)))
{
    got_sigusr1++;
}

static void
usage(void)
{
    /* unusually, we complain to syslog about problems parsing
     * the commandline options; this is because this program
     * is designed to be run from Cyrus' master and to never have
     * a useful controlling terminal */
    syslog(LOG_ERR, "Usage: gdbtramp /full/path/to/cyrus/binary pid\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    const char *binary;
    pid_t pid;
    const char *prog;
    int timeout_sec = 30;
    struct sigaction sa;
    FILE *fp;
    char gdbx_filename[1024];

    openlog("gdbtramp", LOG_PERROR|LOG_PID, LOG_LOCAL6);

    if (argc != 3)
        usage();
    binary = argv[1];
    pid = atoi(argv[2]);
    if (pid <= 0)
        usage();


    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigusr1;
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
    {
        syslog(LOG_ERR, "signal(SIGUSR1): %m");
        exit(1);
    }

    prog = strrchr(binary, '/');
    if (prog)
        prog++;
    else
        prog = binary;

    snprintf(gdbx_filename, sizeof(gdbx_filename),
             "/var/tmp/%s.x", basename(binary));

    fp = fopen(gdbx_filename, "w");
    if (!fp)
    {
        syslog(LOG_ERR, "%s: %m", gdbx_filename);
        exit(1);
    }
    fprintf(fp, "# gdb commands file, written by gdbtramp\n");
    fprintf(fp, "file %s\n", binary);
    fprintf(fp, "attach %d\n", (int)pid);
    fprintf(fp, "shell kill -USR1 %d\n", (int)getpid());
    fprintf(fp, "echo Please set some breakpoints and use the "
                "\"continue\" command\\n\n");
    fclose(fp);

    syslog(LOG_ERR, "You have %d seconds to run gdb "
                    "thus: >>>>   gdb -x %s",
                    timeout_sec, gdbx_filename);
    /* another, different, message just to make sure the syslogd
     * flushes the previous one to the logfile */
    syslog(LOG_ERR, "tick tick tick...");

    /* wait 30 seconds, expecting to be interrupted by a signal */
    poll(NULL, 0, timeout_sec*1000);
    if (!got_sigusr1)
    {
        syslog(LOG_ERR, "You're too slow!");
        exit(1);
    }

    syslog(LOG_ERR, "gdbtramp exiting");
    return 0;
}
