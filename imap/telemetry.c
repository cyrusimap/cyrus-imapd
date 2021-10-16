/* telemetry.c -- common server telemetry
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
#include "telemetry.h"

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
        snprintf(buf, sizeof(buf), "%s%s%s/%s-%lu.%lu",
                 config_dir, FNAME_LOGDIR, userid, config_ident,
                 (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
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
            syslog(LOG_ERR, "IOERROR: unable to write to telemetry log %s: %m", buf);

        if (pin) prot_setlog(pin, fd);
        if (pout) prot_setlog(pout, fd);
    }

    return fd;
}

EXPORTED void telemetry_rusage(const char *userid)
{
    static struct rusage        previous;
    struct rusage               current;
    struct timeval              sys, user;

    if (userid && *userid) {
        if (getrusage(RUSAGE_SELF, &current) != 0) {
            syslog(LOG_ERR, "getrusage: %s", userid);
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
        syslog(LOG_NOTICE, "USAGE %s user: %lu.%.6d sys: %lu.%.6d", userid,
               (unsigned long)user.tv_sec, (int)user.tv_usec,
               (unsigned long)sys.tv_sec, (int)sys.tv_usec);

        previous = current;
    }

    return;
}
