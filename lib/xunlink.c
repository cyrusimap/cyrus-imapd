/* xunlink.c -- error-logging unlink wrapper
 *
 * Copyright (c) 1994-2023 Carnegie Mellon University.  All rights reserved.
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

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/xunlink.h"

EXPORTED int xunlink_fn(const char *sfile, int sline, const char *sfunc,
                        const char *pathname)
{
    int saved_errno, r;

    /* n.b. we don't reset errno before calling unlink, so it might contain
     * stuff from some earlier syscall.  that's fine, because we only examine
     * it when unlink's return value indicates an error, in which case its
     * value is definitely ours.  otherwise we just save and restore it
     * untouched.
     */

    r = unlink(pathname);
    saved_errno = errno;

    if (r) {
        if (saved_errno == ENOENT) {
            /* we usually ignore this case, so reduce errno pollution
             *
             * this means you can't use this wrapper function when you do care
             * about this case
             */
            saved_errno = 0;
            r = 0;
        }
        else {
            /* n.b. not simply using xsyslog, because we want to log our
             * caller's location, but xsyslog would log ours
             */
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

    /* n.b. we don't reset errno before calling unlinkat, so it might contain
     * stuff from some earlier syscall.  that's fine, because we only examine
     * it when unlinkat's return value indicates an error, in which case its
     * value is definitely ours.  otherwise we just save and restore it
     * untouched.
     */

    r = unlinkat(dirfd, pathname, flags);
    saved_errno = errno;

    if (r) {
        if (saved_errno == ENOENT) {
            /* we usually ignore this case, so reduce errno pollution
             *
             * this means you can't use this wrapper function when you do care
             * about this case
             */
            saved_errno = 0;
            r = 0;
        }
        else {
            /* n.b. not simply using xsyslog, because we want to log our
             * caller's location, but xsyslog would log ours
             */
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
