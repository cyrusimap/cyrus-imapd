/* signals.c -- signal handling functions to allow clean shutdown

 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 */
/* $Id: signals.c,v 1.13 2005/02/14 16:26:50 shadow Exp $ */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <syslog.h>

#include "signals.h"
#include "xmalloc.h"
#include "exitcodes.h"

static int gotsignal = 0;

static void sighandler(int sig)
{
    /* syslog(LOG_DEBUG, "got signal %d", sig); */
    gotsignal = sig;
}

static const int catch[] = { SIGHUP, SIGINT, SIGQUIT, 0 };

void signals_add_handlers(int alarm)
{
    struct sigaction action;
    int i;
    
    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESETHAND
    action.sa_flags |= SA_RESETHAND;
#endif

    action.sa_handler = sighandler;

    /* SIGALRM used as a syscall timeout, so we don't set SA_RESTART */
    if (alarm && sigaction(SIGALRM, &action, NULL) < 0) {
	fatal("unable to install signal handler for %d: %m", SIGALRM);
    }

#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif
    
    for (i = 0; catch[i] != 0; i++) {
	if (catch[i] != SIGALRM && sigaction(catch[i], &action, NULL) < 0) {
	    fatal("unable to install signal handler for %d: %m", catch[i]);
	}
    }
}

static shutdownfn *shutdown_cb = NULL;

void signals_set_shutdown(shutdownfn *s)
{
    shutdown_cb = s;
}

int signals_poll(void)
{
    switch (gotsignal) {
    case SIGINT:
    case SIGQUIT:
	if (shutdown_cb) shutdown_cb(EC_TEMPFAIL);
	else exit(EC_TEMPFAIL);
	break;
    default:
	return gotsignal;
	break;
    }
    return 0; /* compiler warning stupidity */
}
