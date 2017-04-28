/* calalarmd.c - daemon for sending calendar alarms
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

#include <sys/types.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <fcntl.h>

#include "sync_log.h"
#include "global.h"
#include "xmalloc.h"
#include "exitcodes.h"
#include "caldav_db.h"
#include "caldav_alarm.h"

extern int optind;
extern char *optarg;

static int debugmode = 0;

EXPORTED void fatal(const char *msg, int err)
{
    if (debugmode) fprintf(stderr, "dying with %s %d\n",msg,err);
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");

    cyrus_done();

    exit(err);
}

static void shut_down(int ec) __attribute__((noreturn));
static void shut_down(int ec)
{
    caldav_done();
    annotatemore_close();
    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    sync_log_done();
    cyrus_done();
    exit(ec);
}

int main(int argc, char **argv)
{
    int opt;
    pid_t pid;
    char *alt_config = NULL;
    time_t runattime = 0;
    int upgrade = 0;

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:dt:U")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'd': /* don't fork. debugging mode */
            debugmode = 1;
            break;
        case 't': /* run a single scan at this time */
            runattime = atoi(optarg);
            break;
        case 'U':
            upgrade = 1;
            break;
        default:
            fprintf(stderr, "invalid argument\n");
            exit(EC_USAGE);
            break;
        }
    }

    cyrus_init(alt_config, "calalarmd", 0, 0);

    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    annotatemore_open();

    caldav_init();

    mboxevent_init();

    sync_log_init();

    if (upgrade) {
        caldav_alarm_upgrade();
        shut_down(0);
    }

    if (runattime) {
        caldav_alarm_process(runattime);
        shut_down(0);
    }

    signals_set_shutdown(shut_down);
    signals_add_handlers(0);

    /* fork unless we were given the -d option or we're running as a daemon */
    if (debugmode == 0 && !getenv("CYRUS_ISDAEMON")) {

        pid = fork();

        if (pid == -1) {
            perror("fork");
            exit(1);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }
    /* child */

    for (;;) {
        struct timeval start, end;
        double totaltime;
        int tosleep;

        signals_poll();

        gettimeofday(&start, 0);
        caldav_alarm_process(0);
        gettimeofday(&end, 0);

        signals_poll();

        totaltime = timesub(&start, &end);
        tosleep = 10 - (int) (totaltime + 0.5); /* round to nearest int */
        if (tosleep > 0)
            sleep(tosleep);
    }

    /* NOTREACHED */
    shut_down(1);
}

