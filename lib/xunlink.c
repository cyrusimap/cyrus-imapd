/* xunlink.c -- error-logging unlink wrapper */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/xunlink.h"

EXPORTED int xunlink_fn(const char *sfile, int sline, const char *sfunc,
                        const char *pathname)
{
    int saved_errno, r;

    saved_errno = errno;
    r = unlink(pathname);

    if (r) {
        if (errno == ENOENT) {
            /* we usually ignore this case, so signal it differently, don't log
             * it as an error, and leave errno intact
             */
            r = 1;
        }
        else {
            /* n.b. not simply using xsyslog, because we want to log our
             * caller's location, but xsyslog would log ours
             */
            saved_errno = errno;
            syslog(LOG_ERR, "IOERROR: unlink failed:"
                            " pathname=<%s> syserror=<%s>"
                            " file=<%s> line=<%d> func=<%s>",
                            pathname, strerror(saved_errno),
                            sfile, sline, sfunc);

            /* if you want to abort() on unlink failure, patch that in here */
        }
    }

    errno = saved_errno;
    return r;
}

EXPORTED int xunlinkat_fn(const char *sfile, int sline, const char *sfunc,
                          int dirfd, const char *pathname, int flags)
{
    int saved_errno, r;

    saved_errno = errno;
    r = unlinkat(dirfd, pathname, flags);

    if (r) {
        if (errno == ENOENT) {
            /* we usually ignore this case, so signal it differently, don't log
             * it as an error, and leave errno intact
             */
            r = 1;
        }
        else {
            /* n.b. not simply using xsyslog, because we want to log our
             * caller's location, but xsyslog would log ours
             */
            saved_errno = errno;
            syslog(LOG_ERR, "IOERROR: unlinkat failed:"
                            " dirfd=<%d> pathname=<%s> flags=<%d> syserror=<%s>"
                            " file=<%s> line=<%d> func=<%s>",
                            dirfd, pathname, flags, strerror(saved_errno),
                            sfile, sline, sfunc);

            /* if you want to abort() on unlinkat failure, patch that in here */
        }
    }

    errno = saved_errno;
    return r;
}
