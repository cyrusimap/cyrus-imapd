/* notify_mailto.c -- email notification method
 * Ken Murchison
 */
/*
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * $Id: notify_mailto.c,v 1.4.2.2 2003/02/06 22:41:04 rjs3 Exp $
 */

#include <config.h>

#include "notify_mailto.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "global.h"
#include "libconfig.h"
#include "rfc822date.h"
#include <sieve_interface.h>

static int global_outgoing_count = 0;

char* notify_mailto(const char *class __attribute__((unused)),
		    const char *priority __attribute__((unused)),
		    const char *user __attribute__((unused)),
		    const char *mailbox __attribute__((unused)),
		    int nopt, char **options,
		    const char *message)
{
    FILE *sm;
    const char *smbuf[10];
    char outmsgid[8192];
    int sm_stat;
    time_t t;
    char datestr[80];
    pid_t sm_pid;
    int fds[2];

    /* XXX check/parse options (mailto URI) */
    if (nopt < 1)
	return strdup("NO mailto URI not specified");

    smbuf[0] = "sendmail";
    smbuf[1] = "-i";		/* ignore dots */
    smbuf[2] = "-f";
    smbuf[3] = "<>";		/* XXX do we want a return-path? */
    smbuf[4] = "--";
    smbuf[5] = options[0];
    smbuf[6] = NULL;

    pipe(fds);
    if ((sm_pid = fork()) == 0) {
	/* i'm the child! run sendmail! */
	close(fds[1]);
	/* make the pipe be stdin */
	dup2(fds[0], 0);
	execv(config_getstring(IMAPOPT_SENDMAIL), (char **) smbuf);

	/* if we're here we suck */
	return strdup("NO mailto couldn't exec");
    }
    /* i'm the parent */
    close(fds[0]);
    sm = fdopen(fds[1], "w");

    if (!sm)
	return strdup("NO mailto could not spawn sendmail process");

    t = time(NULL);
    snprintf(outmsgid, sizeof(outmsgid), "<cmu-sieve-%u-%lu-%d@%s>", 
	     sm_pid, t, global_outgoing_count++, config_servername);
    
    fprintf(sm, "Message-ID: %s\r\n", outmsgid);

    rfc822date_gen(datestr, sizeof(datestr), t);
    fprintf(sm, "Date: %s\r\n", datestr);
    
    fprintf(sm, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(sm, "From: Mail Sieve Subsystem <%s>\r\n", config_getstring(IMAPOPT_POSTMASTER));
    fprintf(sm, "To: <%s>\r\n", options[0]);
    fprintf(sm, "Subject: [SIEVE] New mail notification\r\n");
    fprintf(sm, "\r\n");

    fprintf(sm, "%s\r\n", message);

    fclose(sm);
    while (waitpid(sm_pid, &sm_stat, 0) < 0);

    /* XXX check for sendmail exit code */

    /* XXX add outmsgid to duplicate delivery database to prevent loop */

    return strdup("OK mailto notification successful");
}
