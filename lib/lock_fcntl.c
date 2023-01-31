/* lock_fcntl.c -- Lock files using fcntl()
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "cyr_lock.h"
#include "ptrarray.h"
#include "util.h"

#include <dlfcn.h>
#include <syslog.h>
#include <time.h>

struct lockitem_struct {
    char *filename;
    int fd;
    char ex;
};

static ptrarray_t heldlocks = PTRARRAY_INITIALIZER;

static void printlocks(void)
{
    if (ptrarray_size(&heldlocks) < 2) return;
    struct buf buf = BUF_INITIALIZER;
    int i;
    int haveindex = 0;
    int haveuser = 0;
    int haveconv = 0;
    int havemb = 0;
    for (i = 0; i < ptrarray_size(&heldlocks); i++) {
        struct lockitem_struct *item = ptrarray_nth(&heldlocks, i);
        if (i) buf_putc(&buf, ' ');
        buf_printf(&buf, "%d=<%c:%d:%s>",
                   i, item->ex, item->fd, item->filename);
        if (strstr(item->filename, "*U*")) {
            haveuser = 1;
        }
        if (strstr(item->filename, "cyrus.index") && ! strstr(item->filename, "cyrus.indexed.db")) {
            haveindex = 1;
            if (!haveuser) syslog(LOG_ERR, "LOCKERROR: INDEX WITHOUT USER");
            if (havemb) syslog(LOG_ERR, "LOCKERROR: INDEX INSIDE MB");
        }
        if (strstr(item->filename, "conversations.db")) {
            haveconv = 1;
            if (!haveuser) syslog(LOG_ERR, "LOCKERROR: CONV WITHOUT USER");
            if (havemb) syslog(LOG_ERR, "LOCKERROR: CONV INSIDE MB");
        }
        if (strstr(item->filename, "mailboxes.db")) {
            havemb = 1;
        }
        if (haveconv && havemb && haveindex && haveuser) {
            syslog(LOG_NOTICE, "megalocked");
        }
    }
    syslog(LOG_NOTICE, "LOCKORDER: %s", buf_cstring(&buf));
    buf_free(&buf);
}

static void addlock(const char *filename, int fd, int exclusive)
{
    int i;
    for (i = 0; i < ptrarray_size(&heldlocks); i++) {
        struct lockitem_struct *item = ptrarray_nth(&heldlocks, i);
        if (item->fd != fd) continue;
        syslog(LOG_NOTICE, "LOCKNOTICE: double add %s (%d) - ignoring", filename, fd);
        return; // don't double-lock
    }
    struct lockitem_struct *item = xzmalloc(sizeof(struct lockitem_struct));
    item->filename = xstrdupnull(filename);
    item->fd = fd;
    item->ex = exclusive ? 'E' : 'S';
    ptrarray_append(&heldlocks, item);
    printlocks();
}

static void rmlock(const char *filename, int fd)
{
    int i;
    for (i = 0; i < ptrarray_size(&heldlocks); i++) {
        struct lockitem_struct *item = ptrarray_nth(&heldlocks, i);
        if (item->fd != fd) continue;
        ptrarray_remove(&heldlocks, i);
        if (i < ptrarray_size(&heldlocks))
            syslog(LOG_ERR, "LOCKNOTICE: remove out of order %d=<%c:%d:%s>",
                   i, item->ex, item->fd, item->filename);
        free(item->filename);
        free(item);
        printlocks();
        return;
    }
    syslog(LOG_ERR, "LOCKNOTICE: missing %d:%s", fd, filename);

}

EXPORTED int close(int fd)
{
    int i;
    static int (* fptr)() = 0;
    if (!fptr) {
        fptr = (int (*)())dlsym(RTLD_NEXT, "close");
    }

    for (i = 0; i < ptrarray_size(&heldlocks); i++) {
        struct lockitem_struct *item = ptrarray_nth(&heldlocks, i);
        if (item->fd != fd) continue;
        syslog(LOG_NOTICE, "LOCKNOTICE: removed by close %d", fd);
        ptrarray_remove(&heldlocks, i);
        if (i < ptrarray_size(&heldlocks))
            syslog(LOG_ERR, "LOCKNOTICE: remove out of order %d=<%c:%d:%s>",
                   i, item->ex, item->fd, item->filename);
        free(item->filename);
        free(item);
    }

    return ((*fptr)(fd));
}


EXPORTED void clearlocks(void)
{
    int i;
    for (i = 0; i < ptrarray_size(&heldlocks); i++) {
        struct lockitem_struct *item = ptrarray_nth(&heldlocks, i);
        syslog(LOG_ERR, "LOCKCLEAR: forgetting %d=<%c:%d:%s>",
               i, item->ex, item->fd, item->filename);
        free(item->filename);
        free(item);
    }
    ptrarray_truncate(&heldlocks, 0);
}

EXPORTED const char lock_method_desc[] = "fcntl";

EXPORTED double debug_locks_longer_than = 0.0;

/*
 * Block until we obtain an exclusive lock on the file descriptor 'fd',
 * opened for reading and writing on the file named 'filename'.  If
 * 'filename' is replaced, will re-open it as 'fd' and acquire a lock
 * on the new file.
 *
 * On success, returns 0.  If a pointer to a struct stat is given as
 * 'sbuf', it is filled in.
 *
 * On failure, returns -1 with an error code in errno.  If
 * 'failaction' is provided, it is filled in with a pointer to a fixed
 * string naming the action that failed.
 *
 */
EXPORTED int lock_reopen_ex(int fd, const char *filename,
                            struct stat *sbuf, const char **failaction,
                            int *changed)
{
    int r;
    struct flock fl;
    struct stat sbuffile, sbufspare;
    int newfd;
    struct timeval starttime;
    if (debug_locks_longer_than)
        gettimeofday(&starttime, 0);


    if (!sbuf) sbuf = &sbufspare;

    for (;;) {
        fl.l_type= F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        r = fcntl(fd, F_SETLKW, &fl);
        if (r == -1) {
            if (errno == EINTR) continue;
            if (failaction) *failaction = "locking";
            return -1;
        }
        addlock(filename, fd, /*exclusive*/1);

        r = fstat(fd, sbuf);
        if (!r) r = stat(filename, &sbuffile);
        if (r == -1) {
            if (failaction) *failaction = "stating";
            r = lock_unlock(fd, filename);
            return -1;
        }

        if (sbuf->st_ino == sbuffile.st_ino) {
            if (debug_locks_longer_than) {
                struct timeval endtime;
                gettimeofday(&endtime, 0);
                double locktime = (double)(endtime.tv_sec - starttime.tv_sec) +
                                  (double)(endtime.tv_usec - starttime.tv_usec)/1000000.0;
                if (locktime > debug_locks_longer_than) /* 10ms */
                    syslog(LOG_NOTICE, "locktimer: reopen %s (%0.2fs)", filename, locktime);
            }
            return 0;
        }

        if (changed) *changed = 1;

        newfd = open(filename, O_RDWR);
        if (newfd == -1) {
            if (failaction) *failaction = "opening";
            r = lock_unlock(fd, filename);
            return -1;
        }
        dup2(newfd, fd);
        close(newfd);
    }
}

/*
 * Obtain a lock on 'fd'.  The lock is exclusive if 'exclusive'
 * is true, otherwise shared.  Normally blocks until a lock is
 * obtained, but if 'nonblock' is true does not block and instead
 * fails with errno=EWOUDBLOCK if the lock cannot be obtained.
 *
 * Returns 0 for success, -1 for failure, with errno set to an
 * appropriate error code.
 */
EXPORTED int lock_setlock(int fd, int exclusive, int nonblock,
                          const char *filename)
{
    int r;
    struct flock fl;
    int type = (exclusive ? F_WRLCK : F_RDLCK);
    int cmd = (nonblock ? F_SETLK : F_SETLKW);
    struct timeval starttime;
    if (debug_locks_longer_than)
        gettimeofday(&starttime, 0);

    for (;;) {
        fl.l_type= type;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        r = fcntl(fd, cmd, &fl);
        if (r != -1) {
            addlock(filename, fd, exclusive);
            if (debug_locks_longer_than) {
                struct timeval endtime;
                gettimeofday(&endtime, 0);
                double locktime = (double)(endtime.tv_sec - starttime.tv_sec) +
                                  (double)(endtime.tv_usec - starttime.tv_usec)/1000000.0;
                if (locktime > debug_locks_longer_than)
                    syslog(LOG_NOTICE, "locktimer: reopen %s (%0.2fs)", filename, locktime);
            }
            return 0;
        }
        if (errno == EINTR) continue;
        if (nonblock) {
            syslog(LOG_NOTICE, "LOCKNOTICE: nonblocking attempt <%c:%d:%s>",
                   exclusive ? 'E' : 'S', fd, filename);
            printlocks();
        }
        return -1;
    }
}

/*
 * Release any lock on 'fd'.  Always returns success.
 */
EXPORTED int lock_unlock(int fd, const char *filename)
{
    struct flock fl;
    int r;

    fl.l_type= F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    for (;;) {
        r = fcntl(fd, F_SETLKW, &fl);
        if (r != -1) {
            rmlock(filename, fd);
            return 0;
        }
        if (errno == EINTR) continue;
        /* xxx help! */
        return -1;
    }
}

