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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "assert.h"
#include "idle.h"
#include "idlemsg.h"
#include "global.h"
#include "util.h"

HIDDEN const char *idle_method_desc = "no";

/* link to idled */
static struct sockaddr_un idle_remote;

/* true if we've successfully told the idled
 * that we want to be notified of changes */
static int idle_started;

/* Send the message 'which' about the mailbox 'mboxname' to the idled.
 * Returns 0 on success or an IMAP error code on failure */
static int idle_send_msg(int which, const char *mboxname)
{
    idle_message_t msg;

    /* maybe the idled came along, so we always send anyway, because
     * polled idle is too awful to contemplate */

    /* fill the structure */
    msg.which = which;
    xstrncpy(msg.mboxname, mboxname ? mboxname : ".", sizeof(msg.mboxname));

    /* send */
    return idle_send(&idle_remote, &msg);
}

/*
 * Notify idled of a mailbox change
 */
static void idle_notify(const char *mboxname)
{
    int r;

    /* We should try to determine if we need to send this
     * (ie, is an imapd is IDLE on 'mailbox'?).
     */
    r = idle_send_msg(IDLE_MSG_NOTIFY, mboxname);
    if (r && (r != ENOENT)) {
        /* ENOENT can happen as result of a race between delivering
         * messages and restarting idled.  It indicates that the
         * idled's socket was unlinked, which means that idled went
         * through it's graceful shutdown path, so don't syslog. */
        syslog(LOG_ERR, "IDLE: error sending message "
                        "NOTIFY to idled for mailbox %s: %s.",
                        mboxname, error_message(r));
    }
    if (errno == ENOENT)
        errno = 0;
}

/*
 * Create connection to idled for sending notifications
 */
EXPORTED void idle_init(void)
{
    struct sockaddr_un local;
    int fdflags;
    int s;
    int r;

    if (!idle_enabled()) return;

    r = idle_make_client_address(&local);
    assert(r);
    r = idle_make_server_address(&idle_remote);
    assert(r);

    idle_method_desc = "poll";

    /* set the mailbox update notifier */
    mailbox_set_updatenotifier(idle_notify);

    if (!idle_init_sock(&local))
        return;

    s = idle_get_sock();

    /* put us in non-blocking mode */
    fdflags = fcntl(s, F_GETFD, 0);
    if (fdflags != -1)
        fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags == -1) {
        idle_done_sock();
        return;
    }

    idle_method_desc = "idled";
}

EXPORTED int idle_enabled(void)
{
    int idle_period = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');

    /* only enabled if a positive period */
    return (idle_period > 0);
}

EXPORTED void idle_start(const char *mboxname)
{
    int r;

    if (!idle_enabled()) return;

    /* Tell idled that we're idling.  It doesn't
     * matter if it fails, we'll still poll */
    r = idle_send_msg(IDLE_MSG_INIT, mboxname);
    if (r) {
        int idle_timeout = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');
        syslog(LOG_ERR, "IDLE: error sending message "
                        "INIT to idled for mailbox %s: %s. "
                        "Falling back to polling every %d seconds.",
                        mboxname, error_message(r), idle_timeout);
        return;
    }

    idle_started = 1;
}

EXPORTED int idle_wait(int otherfd)
{
    fd_set rfds;
    int maxfd = -1;
    int s = -1;
    struct timeval timeout;
    int r;
    int flags = 0;
    int idle_timeout = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');

    if (!idle_enabled()) return 0;

    /* If idled was not contacted, we still listen on the socket,
     * because we might get ALERTs, but we won't get mailbox
     * notifications.  The poll timeout controls how quickly
     * we will notice new mail arriving. */

    FD_ZERO(&rfds);
    s = idle_get_sock();
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

    /* maximum possible timeout before we double-check anyway */
    timeout.tv_sec = idle_timeout;
    timeout.tv_usec = 0;

    do {
        r = signals_select(maxfd+1, &rfds, NULL, NULL, &timeout);

        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            syslog(LOG_ERR, "IDLE: select failed: %m");
            return 0;
        }
        if (r == 0) {
            /* timeout */
            flags |= IDLE_MAILBOX|IDLE_ALERT;
        }
        if (r > 0 && s >= 0 && FD_ISSET(s, &rfds)) {
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

EXPORTED void idle_stop(const char *mboxname)
{
    int r;

    if (!idle_started) return;

    /* Tell idled that we're done idling */
    r = idle_send_msg(IDLE_MSG_DONE, mboxname);
    if (r && (r != ENOENT)) {
        /* See comment in idle_notify() about ENOENT */
        syslog(LOG_ERR, "IDLE: error sending message "
                        "DONE to idled for mailbox %s: %s.",
                        mboxname, error_message(r));
    }

    idle_started = 0;
}

EXPORTED void idle_done(void)
{
    /* close the local socket */
    idle_done_sock();
}
