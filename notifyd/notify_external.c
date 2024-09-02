/* notify_external.c -- external notification method
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
