/* telemetry.c - common server telemetry */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>

#include "prot.h"
#include "global.h"

/* create telemetry log; return fd of log */
EXPORTED int telemetry_log(const char *userid, struct protstream *pin,
                  struct protstream *pout, int usetimestamp)
{
    char buf[1024];
    char buf2[1024];
    int fd = -1;
    time_t now;
    int r;

    if (usetimestamp) {
        struct timeval tv;

        gettimeofday(&tv, NULL);

        /* use sec.clocks */
        snprintf(buf, sizeof(buf), "%s%s%s/%s-" TIME_T_FMT ".%.6lu",
                 config_dir, FNAME_LOGDIR, userid, config_ident,
                 tv.tv_sec, (unsigned long)tv.tv_usec);
    }
    else if (config_getswitch(IMAPOPT_TELEMETRY_BYSESSIONID)) {
        const char *sid = session_id();
        /* use pid */
        snprintf(buf, sizeof(buf), "%s%s%s/%s-%s",
                 config_dir, FNAME_LOGDIR, userid, config_ident, sid);
    }
    else {
        /* use pid */
        snprintf(buf, sizeof(buf), "%s%s%s/%s-%lu",
                 config_dir, FNAME_LOGDIR, userid, config_ident,
                 (unsigned long) getpid());
    }

    fd = open(buf, O_CREAT | O_APPEND | O_WRONLY, 0644);

    if (fd != -1) {
        now = time(NULL);
        snprintf(buf2, sizeof(buf2), "---------- %s %s\n",
                 userid, ctime(&now));
        r = write(fd, buf2, strlen(buf2));
        if (r < 0)
            xsyslog_ev(LOG_ERR, "telemetry.write.failed",
                       lf_s("sys.path", buf));

        if (pin) prot_setlog(pin, fd);
        if (pout) prot_setlog(pout, fd);
    }

    return fd;
}

EXPORTED void telemetry_rusage(char *userid)
{
    static struct rusage        previous;
    struct rusage               current;
    struct timeval              sys, user;

    if (userid && *userid) {
        if (getrusage(RUSAGE_SELF, &current) != 0) {
            xsyslog_ev(LOG_ERR, "telemetry.rusage.failed",
                       lf_s("u.username", userid));
            return;
        }

        user.tv_sec = current.ru_utime.tv_sec - previous.ru_utime.tv_sec;
        user.tv_usec = current.ru_utime.tv_usec - previous.ru_utime.tv_usec;
        if (user.tv_usec < 0) {
            user.tv_sec--;
            user.tv_usec += 1000000;
        }

        sys.tv_sec = current.ru_stime.tv_sec - previous.ru_stime.tv_sec;
        sys.tv_usec = current.ru_stime.tv_usec - previous.ru_stime.tv_usec;
        if (sys.tv_usec < 0) {
            sys.tv_sec--;
            sys.tv_usec += 1000000;
        }

        /*
         * Some systems provide significantly more data, but POSIX
         * guarantees user & sys CPU time.
         */
        xsyslog_ev(LOG_INFO, "telemetry.rusage",
                   lf_s("u.username", userid),
                   lf_raw("telemetry.cpu.user", TIME_T_FMT ".%.6d", user.tv_sec, (int)user.tv_usec),
                   lf_raw("telemetry.cpu.sys", TIME_T_FMT ".%.6d", sys.tv_sec, (int)sys.tv_usec));

        previous = current;
    }

    return;
}
