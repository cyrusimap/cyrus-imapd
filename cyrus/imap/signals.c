/* signals.c -- signal handling functions to allow clean shutdown

   insert copyright */

/* $Id: signals.c,v 1.2 2000/02/17 05:24:22 leg Exp $ */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <syslog.h>

#include "config.h"
#include "xmalloc.h"
#include "exitcodes.h"

static int gotsignal = 0;

static void sighandler(int sig)
{
    syslog(LOG_DEBUG, "got signal %d", sig);
    gotsignal = sig;
}

static int catch[] = { SIGHUP, SIGINT, SIGQUIT, 0 };

void signals_add_handlers(void)
{
    struct sigaction action;
    int i;
    
    sigemptyset(&action.sa_mask);

    action.sa_flags = 0;
#ifdef SA_RESETHAND
    action.sa_flags |= SA_RESETHAND;
#endif
#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif

    action.sa_handler = sighandler;
    
    for (i = 0; catch[i] != 0; i++) {
	if (sigaction(catch[i], &action, NULL) < 0) {
	    fatal("unable to install signal handler for %d: %m", catch[i]);
	}
    }
}

static shutdownfn *shutdown = NULL;

void signals_set_shutdown(shutdownfn *s)
{
    shutdown = s;
}

void signals_poll(void)
{
    if (gotsignal) {
	if (shutdown) shutdown(EC_TEMPFAIL);
	else exit(EC_TEMPFAIL);
    }
}
