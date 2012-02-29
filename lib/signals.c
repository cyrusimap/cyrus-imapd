/* signals.c -- signal handling functions to allow clean shutdown
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
 * $Id: signals.c,v 1.15 2008/03/24 17:09:19 murch Exp $
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "signals.h"
#include "xmalloc.h"
#include "exitcodes.h"

#ifndef _NSIG
#define _NSIG 65
#endif
static volatile sig_atomic_t gotsignal[_NSIG];

static void sighandler(int sig)
{
    if (sig < 1 || sig >= _NSIG)
	sig = _NSIG-1;
    gotsignal[sig] = 1;
}

static const int catch[] = { SIGHUP, 0 };

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
	fatal("unable to install signal handler for SIGALRM", EC_TEMPFAIL);
    }

    /* no restartable SIGQUIT thanks */
    if (sigaction(SIGQUIT, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGQUIT", EC_TEMPFAIL);
    if (sigaction(SIGINT, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGINT", EC_TEMPFAIL);
    if (sigaction(SIGTERM, &action, NULL) < 0)
	fatal("unable to install signal handler for SIGTERM", EC_TEMPFAIL);

#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif
    
    for (i = 0; catch[i] != 0; i++) {
	if (catch[i] != SIGALRM && sigaction(catch[i], &action, NULL) < 0) {
	    char buf[256];
	    snprintf(buf, sizeof(buf),
		     "unable to install signal handler for %s: %s",
		     strsignal(catch[i]), strerror(errno));
	    fatal(buf, EC_TEMPFAIL);
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
    int sig;

    if (gotsignal[SIGINT] || gotsignal[SIGQUIT] || gotsignal[SIGTERM]) {
	if (shutdown_cb) shutdown_cb(EC_TEMPFAIL);
	else exit(EC_TEMPFAIL);
    }
    for (sig = 1 ; sig < _NSIG ; sig++) {
	if (gotsignal[sig])
	    return sig;
    }
    return 0;
}
