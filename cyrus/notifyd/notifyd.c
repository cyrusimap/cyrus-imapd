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
 * $Id: notifyd.c,v 1.10.2.5 2003/02/06 22:41:04 rjs3 Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <signal.h>
#include <string.h>

#include "notifyd.h"

#include "exitcodes.h"
#include "global.h"
#include "libconfig.h"
#include "xmalloc.h"


/* global state */
const int config_need_data = 0;

static int soc = 0; /* master has handed us the port as stdin */

static notifymethod_t *default_method;	/* default method daemon is using */


/* Cleanly shut down and exit */
void shut_down(int code) __attribute__ ((noreturn));
void shut_down(int code)
{
    cyrus_done();

    /* done */
    exit(code);
}

char *fetch_arg(char *head, char* tail)
{
    char *cp;

    for (cp = head; *cp && cp < tail; cp++);
    return (cp == tail ? NULL : cp + 1);
}

#define NOTIFY_MAXSIZE 8192

int do_notify()
{
    struct sockaddr_un sun_data;
    socklen_t sunlen = sizeof(sun_data);
    char buf[NOTIFY_MAXSIZE+1], *cp, *tail;
    int r, i;
    char *method, *class, *priority, *user, *mailbox, *message;
    char **options = NULL;
    long nopt;
    char *reply;
    notifymethod_t *nmethod;

    while (1) {
	method = class = priority = user = mailbox = message = reply = NULL;
	nopt = 0;

	signals_poll();
	r = recvfrom(soc, buf, NOTIFY_MAXSIZE, 0,
		     (struct sockaddr *) &sun_data, &sunlen);
	if (r == -1) {
	    return (errno);
	}
	buf[r] = '\0';

	tail = buf + r - 1;

	/*
	 * parse request of the form:
	 *
	 * method NUL class NUL priority NUL user NUL mailbox NUL
	 *   nopt NUL N(option NUL) message NUL
	 */
	method = (cp = buf);

	if (cp) class = (cp = fetch_arg(cp, tail));
	if (cp) priority = (cp = fetch_arg(cp, tail));
	if (cp) user = (cp = fetch_arg(cp, tail));
	if (cp) mailbox = (cp = fetch_arg(cp, tail));

	if (cp) cp = fetch_arg(cp, tail); /* skip to nopt */
	if (cp) nopt = strtol(cp, NULL, 10);
	if (nopt < 0 || errno == ERANGE) cp = NULL;

	if (cp && nopt &&
	    !(options = (char**) xrealloc(options, nopt * sizeof(char*)))) {
	    fatal("xmalloc(): can't allocate options", EC_OSERR);
	}

	for (i = 0; cp && i < nopt; i++) {
	    options[i] = (cp = fetch_arg(cp, tail));
	}

	if (cp) message = (cp = fetch_arg(cp, tail));

	if (!message) {
	    syslog(LOG_ERR, "malformed notify request");
	    return 0;
	}

	if (!*method)
	    nmethod = default_method;
	else {
	    nmethod = methods;
	    while (nmethod->name) {
		if (!strcasecmp(nmethod->name, method)) break;
		nmethod++;
	    }
	}

	syslog(LOG_DEBUG, "do_notify using method '%s'",
	       nmethod->name ? nmethod->name: "unknown");

	if (nmethod->name) {
	    reply = nmethod->notify(class, priority, user, mailbox,
				    nopt, options, message);
	}
#if 0  /* we don't care about responses right now */
	else {
	    reply = strdup("NO unknown notification method");
	    if (!reply) {
		fatal("strdup failed", EC_OSERR);
	    }
	}
#endif

	if (reply) free(reply);
    }

    /* never reached */
    return 0;
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
    char *method = "null";

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "m:")) != EOF) {
	switch(opt) {
	case 'm':
	    method = optarg;
	    break;
	default:
	    usage();
	}
    }

    default_method = methods;
    while (default_method->name) {
	if (!strcasecmp(default_method->name, method)) break;
	default_method++;
    }

    if (!default_method) fatal("unknown notification method %s", EC_USAGE);

    signals_set_shutdown(&shut_down);
    signals_add_handlers();

    return 0;
}

void service_abort(int error)
{
    shut_down(error);
}

int service_main(int argc, char **argv, char **envp)
{
    int r = 0;

    r = do_notify();

    shut_down(r);
}
