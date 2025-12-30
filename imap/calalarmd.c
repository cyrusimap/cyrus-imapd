/* calalarmd.c - daemon for sending calendar alarms */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

static struct namespace calalarmd_namespace;

EXPORTED void fatal(const char *msg, int err)
{
    if (debugmode) fprintf(stderr, "dying with %s %d\n", msg, err);
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");

    cyrus_done();

    if (err != EX_PROTOCOL && config_fatals_abort) abort();

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

    mboxname_init_namespace(&calalarmd_namespace, NAMESPACE_OPTION_ADMIN);
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
        time_t interval = 10;

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
