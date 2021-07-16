/* sync_log.c -- Cyrus synchronization logging functions
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
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

/* YYY Need better quoting for obscure filenames: use literals? */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>

#include "assert.h"
#include "command.h"
#include "sync_log.h"
#include "global.h"
#include "cyr_lock.h"
#include "mailbox.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int sync_log_suppressed = 0;
static strarray_t *channels = NULL;
static strarray_t *unsuppressable = NULL;

static struct buf *rightnow_log = NULL;

static int sync_log_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    sync_log_done();
}

static void init_internal() {
    if (!sync_log_initialized) {
        sync_log_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

EXPORTED void sync_log_init(void)
{
    const char *conf;
    int i;

    /* sync_log_init() may be called more than once */
    if (channels) strarray_free(channels);

    conf = config_getstring(IMAPOPT_SYNC_LOG_CHANNELS);
    if (!conf) conf = "\"\"";
    channels = strarray_split(conf, " ", 0);
    /*
     * The sysadmin can specify "" in the value of sync_log_channels to
     * mean the default channel name - this will be useful for sysadmins
     * who want to start using a sync log channel for squatter but who
     * have been using the default sync log channel for sync_client.
     */
    i = strarray_find(channels, "\"\"", 0);
    if (i >= 0)
        strarray_set(channels, i, NULL);

    strarray_free(unsuppressable);
    unsuppressable = NULL;
    conf = config_getstring(IMAPOPT_SYNC_LOG_UNSUPPRESSABLE_CHANNELS);
    if (conf) {
        unsuppressable = strarray_split(conf, " ", 0);
        i = strarray_find(unsuppressable, "\"\"", 0);
        if (i >= 0)
            strarray_set(unsuppressable, i, NULL);
    }

    conf = config_getstring(IMAPOPT_SYNC_RIGHTNOW_CHANNEL);
    if (conf) {
        rightnow_log = buf_new();
    }

    sync_log_initialized = 1;
}

EXPORTED void sync_log_suppress(void)
{
    sync_log_suppressed = 1;
}

EXPORTED void sync_log_done(void)
{
    sync_log_reset();
    if (rightnow_log) {
        buf_destroy(rightnow_log);
        rightnow_log = NULL;
    }

    strarray_free(channels);
    channels = NULL;

    strarray_free(unsuppressable);
    unsuppressable = NULL;

    sync_log_initialized = 0;
}

static char *sync_log_fname(const char *channel)
{
    static char buf[MAX_MAILBOX_PATH];

    if (channel)
        snprintf(buf, MAX_MAILBOX_PATH,
                 "%s/sync/%s/log", config_dir, channel);
    else
        snprintf(buf, MAX_MAILBOX_PATH,
                 "%s/sync/log", config_dir);

    return buf;
}

static int sync_log_enabled(const char *channel)
{
    if (!config_getswitch(IMAPOPT_SYNC_LOG))
        return 0;       /* entire mechanism is disabled */
    if (!sync_log_suppressed)
        return 1;       /* _suppress() wasn't called */
    if (unsuppressable && strarray_find(unsuppressable, channel, 0) >= 0)
        return 1;       /* channel is unsuppressable */
    return 0;           /* suppressed */
}

static void sync_log_base(const char *channel, const char *string)
{
    int fd;
    struct stat sbuffile, sbuffd;
    int retries = 0;
    const char *fname;

    fname = sync_log_fname(channel);

    while (retries++ < SYNC_LOG_RETRIES) {
        fd = open(fname, O_WRONLY|O_APPEND|O_CREAT, 0640);
        if (fd < 0 && errno == ENOENT) {
            if (!cyrus_mkdir(fname, 0755)) {
                fd = open(fname, O_WRONLY|O_APPEND|O_CREAT, 0640);
            }
        }
        if (fd < 0) {
            syslog(LOG_ERR, "sync_log(): Unable to write to log file %s: %s",
                   fname, strerror(errno));
            return;
        }

        if (lock_blocking(fd, fname) == -1) {
            syslog(LOG_ERR, "sync_log(): Failed to lock %s for %s: %m",
                   fname, string);
            xclose(fd);
            return;
        }

        /* Check that the file wasn't renamed after it was opened above */
        if ((fstat(fd, &sbuffd) == 0) &&
            (stat(fname, &sbuffile) == 0) &&
            (sbuffd.st_ino == sbuffile.st_ino))
            break;

        lock_unlock(fd, fname);
        xclose(fd);
    }
    if (retries >= SYNC_LOG_RETRIES) {
        xclose(fd);
        syslog(LOG_ERR,
               "sync_log(): Failed to lock %s for %s after %d attempts",
               fname, string, retries);
        return;
    }

    if (retry_write(fd, string, strlen(string)) < 0)
        syslog(LOG_ERR, "write() to %s failed: %s",
               fname, strerror(errno));

    (void)fsync(fd); /* paranoia */
    lock_unlock(fd, fname);
    xclose(fd);
}

EXPORTED struct buf *sync_log_rightnow_buf()
{
    if (!channels) return NULL;
    if (!rightnow_log) return NULL;
    if (!buf_len(rightnow_log)) return NULL;
    return rightnow_log;
}

EXPORTED void sync_log_reset()
{
    if (!channels) return;
    if (!rightnow_log) return;
    if (!buf_len(rightnow_log)) return;
    syslog(LOG_NOTICE, "SYNCNOTICE: rightnow log leaked %s", buf_cstring(rightnow_log));
    buf_reset(rightnow_log);
}

static const char *sync_quote_name(const char *name)
{
    static char buf[MAX_MAILBOX_BUFFER+3]; /* "x2 plus \0 */
    char c;
    int src;
    int dst = 0;
    int need_quote = 0;

    /* initial quote */
    buf[dst++] = '"';

    /* degenerate case - no name is the empty string, quote it */
    if (!name || !*name) {
        need_quote = 1;
        goto end;
    }

    for (src = 0; name[src]; src++) {
        c = name[src];
        if ((c == '\r') || (c == '\n'))
            fatal("Illegal line break in folder name", EX_IOERR);

        /* quoteable characters */
        if ((c == '\\') || (c == '\"') || (c == '{') || (c == '}')) {
            need_quote = 1;
            buf[dst++] = '\\';
        }

        /* non-atom characters */
        else if ((c == ' ') || (c == '\t') || (c == '(') || (c == ')')) {
            need_quote = 1;
        }

        buf[dst++] = c;

        if (dst > MAX_MAILBOX_BUFFER)
            fatal("word too long", EX_IOERR);
    }

end:
    if (need_quote) {
        buf[dst++] = '\"';
        buf[dst] = '\0';
        return buf;
    }
    else {
        buf[dst] = '\0';
        return buf + 1; /* skip initial quote */
    }
}

#define BUFSIZE 4096

static char *va_format(const char *fmt, va_list ap)
{
    static char buf[BUFSIZE+1];
    size_t len;
    int ival;
    const char *sval;
    const char *p;

    for (len = 0, p = fmt; *p && len < BUFSIZE; p++) {
        if (*p != '%') {
            buf[len++] = *p;
            continue;
        }
        switch (*++p) {
        case 'd':
            ival = va_arg(ap, int);
            len += snprintf(buf+len, BUFSIZE-len, "%d", ival);
            break;
        case 's':
            sval = va_arg(ap, const char *);
            sval = sync_quote_name(sval);
            strlcpy(buf+len, sval, BUFSIZE-len);
            len += strlen(sval);
            break;
        default:
            buf[len++] = *p;
            break;
        }
    }

    if (buf[len-1] != '\n') buf[len++] = '\n';
    buf[len] = '\0';

    return buf;
}

EXPORTED void sync_log(const char *fmt, ...)
{
    va_list ap;
    const char *val;
    int i;

    init_internal();

    if (!channels) return;

    va_start(ap, fmt);
    val = va_format(fmt, ap);
    va_end(ap);

    if (rightnow_log)
        buf_appendcstr(rightnow_log, val);

    for (i = 0 ; i < channels->count ; i++) {
        const char *channel = channels->data[i];
        if (sync_log_enabled(channel))
            sync_log_base(channel, val);
    }
}

EXPORTED void sync_log_channel(const char *channel, const char *fmt, ...)
{
    va_list ap;
    const char *val;

    init_internal();

    va_start(ap, fmt);
    val = va_format(fmt, ap);
    va_end(ap);

    sync_log_base(channel, val);
}

/*
 * Read-side sync log code
 */
struct sync_log_reader
{
    /*
     * This object works in four modes:
     *
     * - initialised with a sync log channel
     *      - standard mode used by sync_client
     *      - slr->log_file != NULL
     *      - slr->work_file is the name of a rename()d
     *        file that needs to be unlink()ed.
     *      - slr->content_buf is empty
     *
     * - initialised with a saved file name
     *      - used by the sync_client -f option
     *      - slr->log_file = NULL
     *      - slr->work_file is the file given us by the user
     *        which it's important that we do not unlink()
     *      - slr->content_buf is empty
     *
     * - initialised with a file descriptor
     *      - slr->log_file = NULL
     *      - slr->work_file = NULL
     *      - slr->fd is a file descriptor, probably stdin,
     *        and possibly a pipe
     *      - slr->content_buf is empty
     *      - we cannot unlink() anything even if we wanted to.
     *
     * - initialised with the content of a file
     *      - slr->log_file = NULL
     *      - slr->work_file = NULL
     *      - slr->content_buf has a length
     *      - we cannot unlink() anything even if we wanted to.
     */
    char *log_file;
    char *work_file;
    int fd;
    int fd_is_ours;
    struct protstream *input;
    struct buf type;
    struct buf arg1;
    struct buf arg2;
    struct buf contentbuf;
};

static sync_log_reader_t *sync_log_reader_alloc(void)
{
    sync_log_reader_t *slr = xzmalloc(sizeof(sync_log_reader_t));
    slr->fd = -1;
    return slr;
}

/*
 * Create a sync log reader object which will read from the given sync log
 * channel 'channel'.  The channel may be NULL for the default channel.
 * Returns a new object which must be freed with sync_log_reader_free().
 * Does not return NULL.
 */
EXPORTED sync_log_reader_t *sync_log_reader_create_with_channel(const char *channel)
{
    sync_log_reader_t *slr = sync_log_reader_alloc();
    struct buf buf = BUF_INITIALIZER;

    slr->log_file = xstrdup(sync_log_fname(channel));

    /* Create a work log filename.  We will process this
     * first if it exists */
    buf_printf(&buf, "%s-run", slr->log_file);
    slr->work_file = buf_release(&buf);

    return slr;
}

/*
 * Create a sync log reader object which will read from the given file
 * 'filename'.  Returns a new object which must be freed with
 * sync_log_reader_free().  Does not return NULL.
 */
EXPORTED sync_log_reader_t *sync_log_reader_create_with_filename(const char *filename)
{
    sync_log_reader_t *slr = sync_log_reader_alloc();
    slr->work_file = xstrdup(filename);
    /* slr->log_file remain NULL, which matters later */
    return slr;
}

EXPORTED sync_log_reader_t *sync_log_reader_create_with_content(const char *content)
{
    sync_log_reader_t *slr = sync_log_reader_alloc();
    buf_init_ro_cstr(&slr->contentbuf, content);
    return slr;
}

/*
 * Create a sync log reader object which will read from the given file
 * descriptor 'fd'.  The file descriptor must be open for reading and
 * is not closed.  Returns a new object which must be freed with
 * sync_log_reader_free().  Does not return NULL.
 */
EXPORTED sync_log_reader_t *sync_log_reader_create_with_fd(int fd)
{
    sync_log_reader_t *slr = sync_log_reader_alloc();
    slr->fd = fd;
    slr->fd_is_ours = 0;
    /* slr->log_file remain NULL, which matters later */
    return slr;
}

/*
 * Free a sync log reader object.
 */
EXPORTED void sync_log_reader_free(sync_log_reader_t *slr)
{
    if (!slr) return;
    if (slr->input) prot_free(slr->input);
    if (slr->fd_is_ours && slr->fd >= 0) close(slr->fd);
    free(slr->log_file);
    free(slr->work_file);
    buf_free(&slr->type);
    buf_free(&slr->arg1);
    buf_free(&slr->arg2);
    buf_free(&slr->contentbuf);
    free(slr);
}

/*
 * Begin reading a sync log file.  If the reader is reading from a
 * channel, rename the current log file so it will not be appended to by
 * the write side code, and open the file. Otherwise, just open the file
 * (note this is still necessary even when the reader is reading from a
 * file descriptor).
 *
 * When sync_log_reader_begin() returns success, you should loop calling
 * sync_log_reader_getitem() and handling the items, until it returns
 * EOF, and then call sync_log_reader_end().
 *
 * Returns zero on success, IMAP_AGAIN if reading from a channel and
 * there is no current log file, or an IMAP error code on failure.
 */
EXPORTED int sync_log_reader_begin(sync_log_reader_t *slr)
{
    struct stat sbuf;
    int r;

    if (slr->input) {
        r = sync_log_reader_end(slr);
        if (r) return r;
    }

    if (buf_len(&slr->contentbuf)) {
        slr->input = prot_readmap(buf_base(&slr->contentbuf), buf_len(&slr->contentbuf));
        return 0;
    }

    if (stat(slr->work_file, &sbuf) == 0) {
        /* Existing work log file - process this first */
        syslog(LOG_NOTICE,
               "Reprocessing sync log file %s", slr->work_file);
    }
    else if (!slr->log_file) {
        syslog(LOG_ERR, "No sync log filename");
        return IMAP_IOERROR;
    }
    else {
        /* Check for sync_log file */
        if (stat(slr->log_file, &sbuf) < 0) {
            if (errno == ENOENT)
                return IMAP_AGAIN;  /* no problem, try again later */
            syslog(LOG_ERR, "Failed to stat %s: %m",
                   slr->log_file);
            return IMAP_IOERROR;
        }

        /* Move sync_log to our work file */
        if (rename(slr->log_file, slr->work_file) < 0) {
            syslog(LOG_ERR, "Rename %s -> %s failed: %m",
                   slr->log_file, slr->work_file);
            return IMAP_IOERROR;
        }
    }

    if (slr->fd < 0) {
        int fd = open(slr->work_file, O_RDWR, 0);
        if (fd < 0) {
            syslog(LOG_ERR, "Failed to open %s: %m", slr->work_file);
            return IMAP_IOERROR;
        }

        if (lock_blocking(fd, slr->work_file) < 0) {
            syslog(LOG_ERR, "Failed to lock %s: %m", slr->work_file);
            close(fd);
            return IMAP_IOERROR;
        }

        slr->fd = fd;
        slr->fd_is_ours = 1;

        /* we can unlock immediately, since we have serialised
         * any process which held the lock over the rename.  All
         * future attempts to lock this inode will stat and notice
         * the rename, so they won't write any more */
        lock_unlock(slr->fd, slr->work_file);
    }

    slr->input = prot_new(slr->fd, /*write*/0);

    return 0;
}

EXPORTED const char *sync_log_reader_get_file_name(const sync_log_reader_t *slr)
{
    return slr->work_file;
}

/*
 * Finish reading a sync log file.  Closes the file (and, if the reader
 * is reading from a channel, unlinks the work file and prepares for the
 * next file).  Returns 0 on success or an IMAP error code on failure.
 */
EXPORTED int sync_log_reader_end(sync_log_reader_t *slr)
{
    if (!slr->input)
        return 0;

    if (slr->input) {
        prot_free(slr->input);
        slr->input = NULL;
    }

    if (slr->fd_is_ours && slr->fd >= 0) {
        lock_unlock(slr->fd, slr->work_file);
        close(slr->fd);
        slr->fd = -1;
    }

    if (slr->log_file) {
        /* We were initialised with a sync log channel, whose
         * log file we rename()d to the work file.  Now that
         * we've done with the work file we can unlink it.
         * Further checks at this point are just paranoia. */
        if (slr->work_file && unlink(slr->work_file) < 0) {
            syslog(LOG_ERR, "Unlink %s failed: %m", slr->work_file);
            return IMAP_IOERROR;
        }
    }

    return 0;
}

/*
 * Read a single log item from a sync log file.  The item will be
 * returned as three constant strings.  The first string is the type of
 * the item (e.g. "MAILBOX") and is always capitalised.  The second and
 * third strings are arguments.
 *
 * Returns 0 on success, EOF when the end of the file is reached, or an
 * IMAP error code on failure.
 */
EXPORTED int sync_log_reader_getitem(sync_log_reader_t *slr,
                                     const char *args[3])
{
    int c;
    const char *arg1s = NULL;
    const char *arg2s = NULL;

    if (!slr->input)
        return EOF;

    for (;;) {
        if ((c = getword(slr->input, &slr->type)) == EOF)
            return EOF;

        /* Ignore blank lines */
        if (c == '\r') c = prot_getc(slr->input);
        if (c == '\n')
            continue;

        if (c != ' ') {
            syslog(LOG_ERR, "Invalid input");
            eatline(slr->input, c);
            continue;
        }

        if ((c = getastring(slr->input, 0, &slr->arg1)) == EOF) return EOF;
        arg1s = slr->arg1.s;

        arg2s = NULL;
        if (c == ' ') {
            if ((c = getastring(slr->input, 0, &slr->arg2)) == EOF) return EOF;
            arg2s = slr->arg2.s;
        }

        if (c == '\r') c = prot_getc(slr->input);
        if (c != '\n') {
            syslog(LOG_ERR, "Garbage at end of input line");
            eatline(slr->input, c);
            continue;
        }

        break;
    }

    ucase(slr->type.s);
    args[0] = slr->type.s;
    args[1] = arg1s;
    args[2] = arg2s;
    return 0;
}
