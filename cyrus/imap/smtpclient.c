/* smtpclient.c -- Routines for sending a message via SMTP
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
 *
 * $Id: smtpclient.c,v 1.3 2008/03/24 17:09:19 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "smtpclient.h"

extern void fatal(const char *buf, int code);

pid_t open_sendmail(const char *argv[], FILE **sm)
{
    int fds[2];
    FILE *ret;
    pid_t p;

    pipe(fds);
    if ((p = fork()) == 0) {
	/* i'm the child! run sendmail! */
	close(fds[1]);
	/* make the pipe be stdin */
	dup2(fds[0], 0);
	execv(config_getstring(IMAPOPT_SENDMAIL), (char **) argv);

	/* if we're here we suck */
	printf("451 lmtpd: didn't exec() sendmail?!?\r\n");
	fatal("couldn't exec() sendmail", EC_OSERR);
    }

    if (p < 0) {
	/* failure */
	*sm = NULL;
	return p;
    }

    /* parent */
    close(fds[0]);
    ret = fdopen(fds[1], "w");
    *sm = ret;

    return p;
}

/* sendmail_errstr.  create a descriptive message given 'sm_stat': 
   the exit code from wait() from sendmail.

   not thread safe, but probably ok */
char *sendmail_errstr(int sm_stat)
{
    static char errstr[200];

    if (WIFEXITED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process terminated normally, exit status %d\n",
		 WEXITSTATUS(sm_stat));
    } else if (WIFSIGNALED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		"Sendmail process terminated abnormally, signal = %d %s\n",
		WTERMSIG(sm_stat),
#ifdef WCOREDUMP
		WCOREDUMP(sm_stat) ? " -- core file generated" :
#endif
		"");
    } else if (WIFSTOPPED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process stopped, signal = %d\n",
		WTERMSIG(sm_stat));
    } else {
	return NULL;
    }
    
    return errstr;
}
