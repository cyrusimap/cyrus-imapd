/*
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
 * $Id: idle.c,v 1.7 2010/01/06 17:01:32 murch Exp $
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <string.h>

#include "idle.h"
#include "idlemsg.h"
#include "global.h"

const char *idle_method_desc = "no";

/* function to report mailbox updates to the client */
static idle_updateproc_t *idle_update = NULL;

/* how often to poll the mailbox */
static time_t idle_period = -1;
static int idle_started = 0;

/* UNIX socket variables */
static struct sockaddr_un idle_remote;


static int idle_send_msg(int which, const char *mboxname)
{
    idle_message_t msg;

    /* fill the structure */
    msg.which = which;
    msg.pid = getpid();
    strncpy(msg.mboxname, mboxname ? mboxname : ".", sizeof(msg.mboxname));

    /* send */
    return idle_send(&idle_remote, &msg);
}

/*
 * Notify idled of a mailbox change
 */
void idle_notify(const char *mboxname)
{
    /* We should try to determine if we need to send this
     * (ie, is an imapd is IDLE on 'mailbox'?).
     */
    idle_send_msg(IDLE_MSG_NOTIFY, mboxname);
}

/*
 * Create connection to idled for sending notifications
 */
int idle_enabled(void)
{
    if (idle_period == -1) {
	int s;
	int fdflags;
	struct stat sbuf;
	struct sockaddr_un local;

	/* get polling period in case we can't connect to idled
	 * NOTE: if used, a period of zero disables IDLE
	 */
	idle_period = config_getint(IMAPOPT_IMAPIDLEPOLL);
	if (idle_period < 0) idle_period = 0;

	if (!idle_period) return 0;

	idle_method_desc = "poll";

	if (!idle_make_client_address(&local) ||
	    !idle_init_sock(&local))
	    return idle_period;
	s = idle_get_sock();

	if (!idle_make_server_address(&idle_remote))
	    return idle_period;

	/* check that the socket exists */
	if (stat(idle_remote.sun_path, &sbuf) < 0) {
	    idle_done_sock();
	    return idle_period;
	}

	/* put us in non-blocking mode */
	fdflags = fcntl(s, F_GETFD, 0);
	if (fdflags != -1) fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
	if (fdflags == -1) { idle_done_sock(); return idle_period; }

	if (!idle_send_msg(IDLE_MSG_NOOP, NULL)) {
	    idle_done_sock();
	    return idle_period;
	}

	/* set the mailbox update notifier */
	mailbox_set_updatenotifier(idle_notify);

	idle_method_desc = "idled";

	return 1;
    }
    else if (idle_get_sock() != -1) {
	/* if the idle socket is already open, we're enabled */
	return 1;
    }
    else {
	return idle_period;
    }
}

static void idle_handler(int sig)
{
    /* ignore the signals, unless the server has started idling */
    if (!idle_started) return;

    switch (sig) {
    case SIGUSR1:
	idle_update(IDLE_MAILBOX);
	break;
    case SIGUSR2:
	idle_update(IDLE_ALERT);
	break;
    case SIGALRM:
	idle_update(IDLE_MAILBOX|IDLE_ALERT);
	alarm(idle_period);
	break;
    }
}

int idle_init(idle_updateproc_t *proc)
{
    struct sigaction action;

    idle_update = proc;

    /* We don't want recursive calls to idle_update() */
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGUSR1);
    sigaddset(&action.sa_mask, SIGUSR2);
    action.sa_flags = 0;
#ifdef SA_RESTART
    action.sa_flags |= SA_RESTART;
#endif
    action.sa_handler = idle_handler;

    /* Setup the signal handlers */
    if ((sigaction(SIGUSR1, &action, NULL) < 0) ||
	(sigaction(SIGUSR2, &action, NULL) < 0) ||
	(sigaction(SIGALRM, &action, NULL) < 0)) {
	syslog(LOG_ERR, "sigaction: %m");

	/* Cancel receiving signals */
	idle_done(NULL);
	return 0;
    }

    return 1;
}

void idle_start(const char *mboxname)
{
    idle_started = 1;

    /* Tell idled that we're idling */
    if (!idle_send_msg(IDLE_MSG_INIT, mboxname)) {
	/* otherwise, we'll poll with SIGALRM */
	alarm(idle_period);
    }
}

void idle_done(const char *mboxname)
{
    /* Tell idled that we're done idling */
    idle_send_msg(IDLE_MSG_DONE, mboxname);

    /* Cancel alarm */
    alarm(0);

    /* Remove the signal handlers */
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGALRM, SIG_IGN);

    /* close the AF_UNIX socket */
    idle_done_sock();

    idle_update = NULL;
    idle_started = 0;
}
