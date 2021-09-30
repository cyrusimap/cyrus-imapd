/* notifyd.c -- main file for notifyd (notify script notification program)
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>
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

#include "imap/global.h"
#include "libconfig.h"
#include "imap/notify.h"
#include "xmalloc.h"
#include "strarray.h"


/* global state */
const int config_need_data = 0;

static int soc = 0; /* master has handed us the port as stdin */

static notifymethod_t *default_method;  /* default method daemon is using */


/* Cleanly shut down and exit */
void shut_down(int code) __attribute__ ((noreturn));
EXPORTED void shut_down(int code)
{
    in_shutdown = 1;

    cyrus_done();

    /* done */
    exit(code);
}

static char *fetch_arg(char *head, char* tail)
{
    char *cp;

    for (cp = head; *cp && cp < tail; cp++);
    return (cp == tail ? NULL : cp + 1);
}

static int do_notify(void)
{
    struct sockaddr_un sun_data;
    socklen_t sunlen = sizeof(sun_data);
    char buf[NOTIFY_MAXSIZE+1], *cp, *tail;
    int r, i;
    char *method, *class, *priority, *user, *mailbox, *message;
    strarray_t options = STRARRAY_INITIALIZER;
    long nopt;
    char *reply;
    char *fname;
    notifymethod_t *nmethod;
    unsigned bufsiz;
    socklen_t optlen;

    /* Get receive buffer size */
    optlen = sizeof(bufsiz);
    r = getsockopt(soc, SOL_SOCKET, SO_RCVBUF, &bufsiz, &optlen);
    if (r == -1) {
        syslog(LOG_ERR, "unable to getsockopt(SO_RCVBUF) on notify socket: %m");
        return (errno);
    }

    /* Use minimum of 1/10 of receive buffer size (-overhead) NOTIFY_MAXSIZE */
    bufsiz = MIN(bufsiz / 10 - 32, NOTIFY_MAXSIZE);

    while (1) {
        method = class = priority = user = mailbox = message = reply = NULL;
        nopt = 0;

        if (signals_poll() == SIGHUP) {
            /* caught a SIGHUP, return */
            return 0;
        }
        r = recvfrom(soc, buf, bufsiz, 0,
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

        for (i = 0; cp && i < nopt; i++)
            strarray_append(&options, cp = fetch_arg(cp, tail));

        if (cp) message = (cp = fetch_arg(cp, tail));
        if (cp) fname = (cp = fetch_arg(cp, tail));

        if (!message) {
            syslog(LOG_ERR, "malformed notify request");
            strarray_fini(&options);
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
                                    nopt, options.data, message, fname);
        }
#if 0  /* we don't care about responses right now */
        else {
            reply = strdup("NO unknown notification method");
            if (!reply) {
                fatal("strdup failed", EX_OSERR);
            }
        }
#endif

        free(reply);
        strarray_fini(&options);
    }

    /* never reached */
}


EXPORTED void fatal(const char *s, int code)
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

static void usage(void)
{
    syslog(LOG_ERR, "usage: notifyd [-C <alt_config>]");
    exit(EX_USAGE);
}

EXPORTED int service_init(int argc, char **argv, char **envp __attribute__((unused)))
{
    int opt;
    const char *method = "null";

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

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

    if (!default_method) fatal("unknown notification method %s", EX_USAGE);

    signals_set_shutdown(&shut_down);

    return 0;
}

/* Called by service API to shut down the service */
EXPORTED void service_abort(int error)
{
    shut_down(error);
}

EXPORTED int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    int r = 0;

    r = do_notify();

    shut_down(r);
    return 0;
}
