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
#include <errno.h>

#include "idle.h"
#include "idlemsg.h"
#include "global.h"

const char *idle_method_desc = "no";

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

void idle_start(const char *mboxname)
{
    idle_started = 1;

    /* Tell idled that we're idling.  It doesn't
     * matter if it fails, we'll still poll */
    idle_send_msg(IDLE_MSG_INIT, mboxname);
}

int idle_wait(int otherfd)
{
    int s = idle_get_sock();
    fd_set rfds;
    int maxfd;
    struct timeval timeout;
    int r;
    int flags = 0;

    if (!idle_started)
	return 0;

    do {
	FD_ZERO(&rfds);
	maxfd = -1;
	if (s >= 0) {
	    FD_SET(s, &rfds);
	    maxfd = MAX(maxfd, s);
	}
	if (otherfd >= 0) {
	    FD_SET(otherfd, &rfds);
	    maxfd = MAX(maxfd, otherfd);
	}

	/* Note: it's technically valid for there to be no fds to listen
	 * to, in the case where @otherfd is passed as -1 and we failed
	 * to talk to idled.  It shouldn't happen though as we're always
	 * called with a valid otherfd.  */

	/* TODO: this is wrong, we actually want a rolling period */
	timeout.tv_sec = idle_period;
	timeout.tv_usec = 0;

	r = select(maxfd+1, &rfds, NULL, NULL, &timeout);
	if (r < 0) {
	    if (errno == EAGAIN || errno == EINTR)
		continue;
	    syslog(LOG_ERR, "select: %m");
	    return 0;
	}
	if (r == 0) {
	    /* timeout */
	    flags |= IDLE_MAILBOX|IDLE_ALERT;
	}
	if (r > 0 && FD_ISSET(idle_get_sock(), &rfds)) {
	    struct sockaddr_un from;
	    idle_message_t msg;

	    if (idle_recv(&from, &msg)) {
		switch (msg.which) {
		case IDLE_MSG_NOTIFY:
		    flags |= IDLE_MAILBOX;
		    break;
		case IDLE_MSG_ALERT:
		    flags |= IDLE_ALERT;
		    break;
		}
	    }
	}
	if (r > 0 && otherfd >= 0 && FD_ISSET(otherfd, &rfds))
	    flags |= IDLE_INPUT;
    } while (!flags);

    return flags;
}

void idle_done(const char *mboxname)
{
    /* Tell idled that we're done idling */
    idle_send_msg(IDLE_MSG_DONE, mboxname);

    /* close the AF_UNIX socket */
    idle_done_sock();

    idle_started = 0;
}
