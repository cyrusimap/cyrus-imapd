/* lock_file.c -- module for use of dedicated lock files
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "lib/exitcodes.h"
#include "lib/lock_file.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#ifndef LIB_LOCK_FILE_TIMEOUT
#define LIB_LOCK_FILE_TIMEOUT (15) /* 15 seconds is a while, whatever */
#endif

struct lockf {
    char *filename;
    int fd;
    struct timespec ts;
};

static pid_t readpid(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    struct buf buf = BUF_INITIALIZER;
    pid_t r = -1;
    if (buf_getline(&buf, f))
        r = atoi(buf_release(&buf));

    fclose(f);
    return r;
}

EXPORTED struct lockf *lf_lock(const char *filename)
{
    struct stat sbuf;
    int stale_warned = 0;

    struct lockf *lf = xzmalloc(sizeof(*lf));
    if (!lf) return NULL;

    lf->filename = xstrdup(filename);
    if (!lf->filename) goto error;

    time_t attempt_start = time(NULL);

    while ((lf->fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
        if (errno != EEXIST) {
            syslog(LOG_ERR, "unable to lock %s: %m", filename);
            goto error;
        }

        if (attempt_start + LIB_LOCK_FILE_TIMEOUT < time(NULL)) {
            syslog(LOG_ERR, "timed out while attempting to lock %s", filename);
            goto error;
        }

        pid_t lock_holder = readpid(filename);

        if (lock_holder == getpid()) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "deadlock detected: trying to lock %s twice from pid %i\n",
                       filename, getpid());
            fatal(buf_release(&buf), EC_SOFTWARE);
        }

        if (!stale_warned && stat(filename, &sbuf) == 0) {
            int stale_seconds = time(NULL) - sbuf.st_mtime;

            if (stale_seconds > LIB_LOCK_FILE_TIMEOUT) {
                syslog(LOG_WARNING,
                       "stale lock file detected: %s untouched by pid %i in %i seconds",
                       filename, lock_holder, stale_seconds);
                stale_warned++;
            }
        }

        sleep(2);
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%i\n", getpid());
    write(lf->fd, buf_cstring(&buf), buf_len(&buf));
    buf_free(&buf);

    fstat(lf->fd, &sbuf);
    memcpy(&lf->ts, &sbuf.st_mtim, sizeof(lf->ts));

    return lf;

error:
    if (lf->filename) free(lf->filename);
    free(lf);
    return NULL;
}

EXPORTED int lf_ismine(struct lockf *lf)
{
    struct stat sbuf1, sbuf2;

    if (fstat(lf->fd, &sbuf1) < 0) return 0;
    if (lf->ts.tv_sec != sbuf1.st_mtim.tv_sec) return 0;
    if (lf->ts.tv_nsec != sbuf1.st_mtim.tv_nsec) return 0;

    if (stat(lf->filename, &sbuf2) < 0) return 0;
    if (sbuf1.st_ino != sbuf2.st_ino) return 0;

    if (readpid(lf->filename) != getpid()) return 0;

    return 1;
}

EXPORTED int lf_touch(struct lockf *lf)
{
    if (!lf_ismine(lf)) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s: lock no longer ours: %s", __func__, lf->filename);
        fatal(buf_release(&buf), EC_SOFTWARE);
    }

    int r = futimes(lf->fd, NULL);
    if (r) return r;

    struct stat sbuf;
    r = fstat(lf->fd, &sbuf);
    if (r) return r;

    memcpy(&lf->ts, &sbuf.st_mtim, sizeof(lf->ts));

    return 0;
}

EXPORTED time_t lf_age(struct lockf *lf, struct timespec *agep)
{
    if (!lf_ismine(lf)) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s: lock no longer ours: %s", __func__, lf->filename);
        fatal(buf_release(&buf), EC_SOFTWARE);
    }

    time_t age_seconds = time(NULL) - lf->ts.tv_sec;

    if (agep) {
        /*
        * XXX: would be nice to calculate age as struct timespec
        * and pass it back properly in *agep, but portability?
        */
        agep->tv_sec = age_seconds;
        agep->tv_nsec = 0;
    }

    return age_seconds;
}

EXPORTED int lf_unlock(struct lockf **lfp)
{
    struct lockf *lf = *lfp;

    if (!lf_ismine(lf)) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s: lock no longer ours: %s", __func__, lf->filename);
        fatal(buf_release(&buf), EC_SOFTWARE);
    }

    *lfp = NULL;

    unlink(lf->filename);
    free(lf->filename);
    free(lf);
    return 0;
}
