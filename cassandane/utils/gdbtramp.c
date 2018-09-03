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
