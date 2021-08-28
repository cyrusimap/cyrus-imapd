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
#include <sysexits.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <fcntl.h>

#include "global.h"
#include "xmalloc.h"
#include "caldav_db.h"
#include "caldav_alarm.h"

extern int optind;
extern char *optarg;

static int debugmode = 0;

struct namespace calalarmd_namespace;

EXPORTED void fatal(const char *msg, int err)
{
    if (debugmode) fprintf(stderr, "dying with %s %d\n", msg, err);
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");

    cyrus_done();

    exit(err);
}

static void shut_down(int ec) __attribute__((noreturn));
static void shut_down(int ec)
{
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
            exit(EX_USAGE);
            break;
        }
    }

    cyrus_init(alt_config, "calalarmd", 0, 0);

    mboxname_init_namespace(&calalarmd_namespace, /*isadmin*/1);
    mboxevent_setnamespace(&calalarmd_namespace);

    if (upgrade) {
        caldav_alarm_upgrade();
        shut_down(0);
    }

    if (runattime) {
        caldav_alarm_process(runattime, NULL, /*dryrun*/0);
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
        time_t interval = 1;

        signals_poll();

        gettimeofday(&start, 0);
        caldav_alarm_process(0, &interval, /*dryrun*/0);
        libcyrus_run_delayed();
        gettimeofday(&end, 0);

        signals_poll();

        totaltime = timesub(&start, &end);
        tosleep = interval - (int) (totaltime + 0.5); /* round to nearest int */
        if (tosleep > 0)
            sleep(tosleep);

        session_new_id();  // so we know which actions happened in the same run
    }

    /* NOTREACHED */
    shut_down(1);
}
