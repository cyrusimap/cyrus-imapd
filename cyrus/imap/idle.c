/* 
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

/* $Id: idle.c,v 1.2.2.1 2003/10/22 20:13:06 ken3 Exp $ */

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

#include "idle.h"
#include "idled.h"
#include "global.h"

const char *idle_method_desc = "poll";

/* UNIX socket variables */
static int notify_sock = -1;
static struct sockaddr_un idle_remote;
static int idle_remote_len = 0;

/*
 * Send a message to idled
 */
static int idle_send_msg(int msg, struct mailbox *mailbox)
{
    idle_data_t idledata;

    /* fill the structure */
    idledata.msg = msg;
    idledata.pid = getpid();
    strcpy(idledata.mboxname, mailbox ? mailbox->name : ".");

    /* send */
    if (sendto(notify_sock, (void *) &idledata,
	       IDLEDATA_BASE_SIZE+strlen(idledata.mboxname)+1, /* 1 for NULL */
	       0, (struct sockaddr *) &idle_remote, idle_remote_len) == -1) {
      syslog(LOG_ERR, "error sending to idled: %x", msg);
      return 0;
    }

    return 1;
}

/*
 * Notify idled of a mailbox change
 */
void idle_notify(struct mailbox *mailbox)
{
    /* We should try to determine if we need to send this
     * (ie, is an imapd is IDLE on 'mailbox'?).
     */
    idle_send_msg(IDLE_NOTIFY, mailbox);
}

/*
 * Create connection to idled for sending notifications
 */
int idle_init(void)
{
    int s;
    int fdflags;
    struct stat sbuf;
    const char *idle_sock;

    /* if the socket is already open, return */
    if (notify_sock != -1) return 1;

    /* open the socket */
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) return 0;

    idle_remote.sun_family = AF_UNIX;
    idle_sock = config_getstring(IMAPOPT_IDLESOCKET);
    if (idle_sock) {	
	strcpy(idle_remote.sun_path, idle_sock);
    }
    else {
	strcpy(idle_remote.sun_path, config_dir);
	strcat(idle_remote.sun_path, FNAME_IDLE_SOCK);
    }
    idle_remote_len = sizeof(idle_remote.sun_family) +
	strlen(idle_remote.sun_path) + 1;

    /* check that the socket exists */
    if (stat(idle_remote.sun_path, &sbuf) < 0) {
	close(s);
	return 0;
    }

    /* put us in non-blocking mode */
    fdflags = fcntl(s, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags == -1) {
	close(s);
	return 0;
    }

    notify_sock = s;

    /* set the mailbox update notifier */
    mailbox_set_updatenotifier(idle_notify);

    idle_method_desc = "idled";

    return 1;
}

static void idle_handler(int sig) { /* do nothing */ }

void idle_start(struct mailbox *mailbox)
{
    struct sigaction action;

    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = idle_handler;

    /* Tell idled that we're idling */
    if (idle_send_msg(IDLE_INIT, mailbox)) {
	/* if we can talk to idled, setup the signal handlers */
	if ((sigaction(SIGUSR1, &action, NULL) < 0) ||
	    (sigaction(SIGUSR2, &action, NULL) < 0)) {
	    syslog(LOG_ERR, "sigaction: %m");
	}
    }
}

void idle_done(struct mailbox *mailbox)
{
    /* Tell idled that we're done idling */
    idle_send_msg(IDLE_DONE, mailbox);

    /* Remove the signal handlers */
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
}
