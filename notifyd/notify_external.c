/* notify_external.c -- external notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>

#include "imap/global.h"
#include "libconfig.h"
#include "notify_external.h"

char* notify_external(const char *class, const char *priority,
                      const char *user, const char *mailbox,
                      int nopt __attribute__((unused)),
                      char **options __attribute__((unused)),
                      const char *message, const char *fname)
{
    const char *notify;
    const char *buf[12];
    int fds[2], status;
    pid_t child_pid;
    FILE *stream;

    /* check/parse options */
    if (!(notify = config_getstring(IMAPOPT_NOTIFY_EXTERNAL))) {
        syslog(LOG_ERR, "ERROR: no external recipient (program) specified");
        return strdup("NO Recipient unspecified");
    }

    buf[0] = notify;
    buf[1] = "-c";
    buf[2] = class;
    buf[3] = "-p";
    buf[4] = priority;
    buf[5] = "-u";
    buf[6] = user;
    buf[7] = "-m";
    buf[8] = mailbox;
    buf[9] = "-f";
    buf[10] = fname;
    buf[11] = NULL;

    if (pipe(fds) < 0) {
       syslog(LOG_ERR,
              "notify_external: pipe() returned %s", strerror(errno));
       return strdup("NO notify_external pipe failed");
    }

    if ((child_pid = fork()) == 0) {
        /* i'm the child! run notify */
        close(fds[1]);
        /* make the pipe be stdin */
        dup2(fds[0], STDIN_FILENO);
        execv(notify, (char **) buf);

        /* should never reach here */
        syslog(LOG_ERR, "notify_external: exec returned %s", strerror(errno));
        return strdup("NO notify_external exec failed");
    }
    /* i'm the parent */
    close(fds[0]);
    stream = fdopen(fds[1], "w");

    if (!stream) {
        return strdup("NO notify_external could not open stream");
    }

    fprintf(stream, "%s\n", message);

    fclose(stream);
    while (waitpid(child_pid, &status, 0) < 0);

    return strdup("OK notify_external notification successful");
}
