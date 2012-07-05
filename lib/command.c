/* command.c -- utility functions for running commands
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#include <sys/types.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/wait.h>

#include "imap/imap_err.h"
#include "signals.h"
#include "strarray.h"

EXPORTED int run_command(const char *argv0, ...)
{
    va_list va;
    const char *p;
    strarray_t argv = STRARRAY_INITIALIZER;
    pid_t pid;
    int r = 0;

    strarray_append(&argv, argv0);

    va_start(va, argv0);
    while ((p = va_arg(va, const char *)))
	strarray_append(&argv, p);
    va_end(va);

    pid = fork();
    if (pid < 0) {
	syslog(LOG_ERR, "Failed to fork: %m");
	r = IMAP_SYS_ERROR;
	goto out;
    }

    if (!pid) {
	/* in child */
	r = execv(argv0, argv.data);
	syslog(LOG_ERR, "Failed to execute %s: %m", argv0);
	exit(1);
    }
    else {
	/* in parent */
	for (;;) {
	    int status;
	    pid_t pr = waitpid(pid, &status, 0);
	    if (pr < 0) {
		if (errno == EINTR) {
		    signals_poll();
		    continue;
		}
		else if (errno == ECHILD || errno == ESRCH) {
		    r = 0;
		    break;  /* someone else reaped the child */
		}
		else {
		    syslog(LOG_ERR, "waitpid() failed: %m");
		    r = IMAP_SYS_ERROR;
		    break;
		}
	    }
	    if (WIFEXITED(status)) {
		r = 0;
		if (WEXITSTATUS(status)) {
		    syslog(LOG_ERR, "Program %s (pid %d) exited with status %d",
			   argv0, (int)pid, WEXITSTATUS(status));
		    r = IMAP_SYS_ERROR;
		}
		break;
	    }
	    if (WIFSIGNALED(status)) {
		syslog(LOG_ERR, "Program %s (pid %d) died with signal %d",
		       argv0, (int)pid, WTERMSIG(status));
		r = IMAP_SYS_ERROR;
		break;
	    }
	}
    }

out:
    strarray_fini(&argv);
    return r;
}
