/* notifyd.c -- main file for notifyd (notify script notification program)
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
 * $Id: notifyd.c,v 1.1 2002/02/22 22:59:39 ken3 Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "notify.h"
#include "retry.h"
#include "imapconf.h"
#include "xmalloc.h"
#include "exitcodes.h"


static int notifyd_out;
static int notifyd_in;

notifymethod_t *default_method = NULL;	/* default method daemon is using */


/* Reset for the next connection */
static void notifyd_reset(void)
{
    close(0);
    close(1);
    close(2);
}

/* Cleanly shut down and exit */
void shut_down(int code)
{
    /* cleanup */
    notifyd_reset();

    /* done */
    exit(code);
}

void do_notify()
{
    int rc, i;
    char *method = NULL;
    unsigned short nopt;
    char **options = NULL;
    char *priority = NULL;
    char *message = NULL;
    char *reply;
    unsigned short count;
    struct iovec iov[2];
    int num_iov = 0;

    /*
     * read request of the form:
     *
     * count method nopt N(count option) count priority count message
     */

    rc = (retry_read(notifyd_in, &count, sizeof(count)) < (int) sizeof(count));
    if (!rc) {
	count = ntohs(count);
	if ((method = (char*) xmalloc(count+1)) == NULL)
	    fatal("can not allocate method", EX_OSERR);
	if (!rc) {
	    rc = (retry_read(notifyd_in, method, count) < (int) count);
	    method[count] = '\0';
	}
    }

    if (!rc)
	rc = (retry_read(notifyd_in, &nopt, sizeof(nopt)) < (int) sizeof(nopt));
    if (!rc) {
	nopt = ntohs(nopt);
	if ((options = (char**) xmalloc(nopt * sizeof(char*))) == NULL)
	    fatal("can not allocate options", EX_OSERR);

	for (i = 0; !rc && i < nopt; i++) {
	    rc = (retry_read(notifyd_in, &count, sizeof(count)) < (int) sizeof(count));
	    if (!rc) {
		count = ntohs(count);
		if ((options[i] = (char*) xmalloc(count+1)) == NULL)
		    fatal("can not allocate option[i]", EX_OSERR);
		if (!rc) {
		    rc = (retry_read(notifyd_in, options[i], count) < (int) count);
		    options[i][count] = '\0';
		}
	    }
	}
    }

    if (!rc)
	rc = (retry_read(notifyd_in, &count, sizeof(count)) < (int) sizeof(count));
    if (!rc) {
	count = ntohs(count);
	if ((priority = (char*) xmalloc(count+1)) == NULL)
	    fatal("can not allocate priority", EX_OSERR);
	if (!rc) {
	    rc = (retry_read(notifyd_in, priority, count) < (int) count);
	    priority[count] = '\0';
	}
    }

    if (!rc)
	rc = (retry_read(notifyd_in, &count, sizeof(count)) < (int) sizeof(count));
    if (!rc) {
	count = ntohs(count);
	if ((message = (char*) xmalloc(count+1)) == NULL)
	    fatal("can not allocate message", EX_OSERR);
	if (!rc) {
	    rc = (retry_read(notifyd_in, message, count) < (int) count);
	    message[count] = '\0';
	}
    }

    if (rc) syslog(LOG_ERR, "do_notify read failed: %m");

    reply = methods[0].notify(nopt, options, priority, message);

    if (method) free(method);
    if (priority) free(priority);
    if (message) free(message);
    for (i = 0; i < nopt; i++) {
	if (options[i]) free(options[i]);
    }
    if (options) free(options);

    /*
     * send response of the form:
     *
     * count result
     */
    count = htons(strlen(reply));

    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &count, sizeof(count));
    WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, reply);
    rc = retry_writev(notifyd_out, iov, num_iov);

    if (rc == -1) syslog(LOG_ERR, "do_notify write failed: %m");
}


void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;

    syslog(LOG_ERR, "Fatal error: %s", s);

    shut_down(code);
}

void usage(void)
{
    syslog(LOG_ERR, "usage: notifyd [-C <alt_config>]");
    exit(EC_USAGE);
}

int service_init(int argc, char **argv, char **envp)
{
    int opt;

    config_changeident("notifyd");
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* set signal handlers */
    signal(SIGPIPE, SIG_IGN);

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch(opt) {
	case 'C': /* alt config file - handled by service::main() */
	    break;

	default:
	    usage();
	}
    }

    return 0;
}

void service_abort(int error)
{
    shut_down(error);
}

int service_main(int argc, char **argv, char **envp)
{
    /* set up the prot streams */
    notifyd_in = 0;
    notifyd_out = 1;

    do_notify();

    /* cleanup */
/*    notifyd_reset();*/
    shut_down(0);

    return 0;
}
