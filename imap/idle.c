/* idle.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
static int idle_started = 0;

/*
 * Notify idled of a mailbox change
 */
static void idle_notify(json_t *msg)
{
    int r;

    r = idle_send(&idle_remote, msg);
    if (r && (r != ENOENT)) {
        /* ENOENT can happen as result of a race between delivering
         * messages and restarting idled.  It indicates that the
         * idled's socket was unlinked, which means that idled went
         * through it's graceful shutdown path, so don't syslog. */
        pid_t pid = json_integer_value(json_object_get(msg, "pid"));

        syslog(LOG_ERR, "IDLE: error sending message "
                        "NOTIFY to idled for pid %d: %s.",
                        pid, error_message(r));
    }
    if (errno == ENOENT)
        errno = 0;
}

/*
 * Create connection to idled for sending notifications
 */
EXPORTED int idle_init(void)
{
    struct sockaddr_un local;
    int fdflags;
    int s;
    int r;

    if (!idle_enabled()) return -1;

    r = idle_make_client_address(&local);
    assert(r);
    r = idle_make_server_address(&idle_remote);
    assert(r);

    idle_method_desc = "poll";

    if (!idle_init_sock(&local))
        return -1;

    s = idle_get_sock();

    /* put us in non-blocking mode */
    fdflags = fcntl(s, F_GETFD, 0);
    if (fdflags != -1)
        fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags == -1) {
        idle_done_sock();
        return -1;
    }

    /* set the mboxvent idle notifier */
    mboxevent_set_idlenotifier(idle_notify);

    idle_method_desc = "idled";

    return s;
}

EXPORTED int idle_enabled(void)
{
    int idle_period = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');

    /* only enabled if a positive period */
    return (idle_period > 0);
}

EXPORTED int idle_start(unsigned long events, time_t timeout,
                        mailbox_filter_t filter, strarray_t *keys)
{
    int r;

    if (!idle_enabled()) return 0;

    json_t *array = json_array();
    int i;

    for (i = 0; i < strarray_size(keys); i++) {
        json_array_append_new(array, json_string(strarray_nth(keys, i)));
    }

    pid_t pid = getpid();
    json_t *msg = json_pack("{ s:s s:i s:i s:i s:i s:o }",
                           "@type", "start", "pid", getpid(),
                            "events", events, "timeout", timeout,
                            "filter", filter, "keys", array);

    /* Tell idled that we're idling.  It doesn't
     * matter if it fails, we'll still poll */
    r = idle_send(&idle_remote, msg);
    json_decref(msg);

    if (r) {
        int idle_timeout = config_getduration(IMAPOPT_IMAPIDLEPOLL, 's');
        syslog(LOG_ERR, "IDLE: error sending message "
                        "INIT to idled for pid %d: %s. "
                        "Falling back to polling every %d seconds.",
                        pid, error_message(r), idle_timeout);
        return 0;
    }

    idle_started |= filter;

    return 1;
}

EXPORTED json_t *idle_get_message(void)
{
    struct sockaddr_un from;

    return idle_recv(&from);
}

EXPORTED void idle_stop(mailbox_filter_t filter)
{
    int r;

    if (!idle_started) return;

    pid_t pid = getpid();
    json_t *msg = json_pack("{ s:s s:i s:i }",
                            "@type", "stop", "pid", pid, "filter", filter);

    /* Tell idled that we're done idling */
    r = idle_send(&idle_remote, msg);
    json_decref(msg);

    if (r && (r != ENOENT)) {
        /* See comment in idle_notify() about ENOENT */
        syslog(LOG_ERR, "IDLE: error sending message "
                        "DONE to idled for pid %d: %s.",
                        pid, error_message(r));
    }

    if (filter == FILTER_NONE)
        idle_started = 0;
    else
        idle_started &= ~filter;
}

EXPORTED void idle_done(void)
{
    /* close the local socket */
    idle_done_sock();
}
