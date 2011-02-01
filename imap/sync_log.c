/* sync_log.c -- Cyrus synchonization logging functions
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
 * $Id: sync_log.c,v 1.7 2010/01/06 17:01:41 murch Exp $
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
#include <syslog.h>
#include <errno.h>

#include "assert.h"
#include "sync_log.h"
#include "global.h"
#include "cyr_lock.h"
#include "mailbox.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

static int sync_log_enabled = 0;
static const char *suppressed_channel = NULL;
static char *channel_base;
static char *channel_end;

void sync_log_init(void)
{
    char *p;

    sync_log_enabled = config_getswitch(IMAPOPT_SYNC_LOG);
    channel_base = NULL;
    channel_end = NULL;
    if (config_getstring(IMAPOPT_SYNC_LOG_CHANNELS)) {
	channel_base = xstrdup(config_getstring(IMAPOPT_SYNC_LOG_CHANNELS));
	channel_end = channel_base + strlen(channel_base);
	p = channel_base;
	while (*p) {
	    if (*p == ' ') *p = '\0';
	    p++;
	}
    }
}

void sync_log_suppress(void)
{
    sync_log_enabled = 0;
}

void sync_log_suppress_channel(const char *channelname)
{
    if (channelname) {
	/* there can only be one */
	assert (!suppressed_channel);
	suppressed_channel = channelname;
    }
    else {
	suppressed_channel = NULL;
    }
}

void sync_log_done(void)
{
    free(channel_base);
    channel_base = NULL;
}

char *sync_log_fname(const char *channel)
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

static void sync_log_base(const char *channel, const char *string)
{
    int fd;
    struct stat sbuffile, sbuffd;
    int retries = 0;
    const char *fname;

    /* are we being supressed? */
    if (!sync_log_enabled) return;
    if (channel && suppressed_channel && !strcmp(channel, suppressed_channel))
	return;

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

	if (lock_blocking(fd) == -1) {
	    syslog(LOG_ERR, "sync_log(): Failed to lock %s for %s: %m",
		   fname, string);
	    close(fd);
	    return;
	}

	/* Check that the file wasn't renamed after it was opened above */
	if ((fstat(fd, &sbuffd) == 0) &&
	    (stat(fname, &sbuffile) == 0) &&
	    (sbuffd.st_ino == sbuffile.st_ino))
	    break;

	close(fd);
    }
    if (retries >= SYNC_LOG_RETRIES) {
	close(fd);
	syslog(LOG_ERR,
	       "sync_log(): Failed to lock %s for %s after %d attempts",
	       fname, string, retries);
	return;
    }

    if (retry_write(fd, string, strlen(string)) < 0)
	syslog(LOG_ERR, "write() to %s failed: %s",
	       fname, strerror(errno));

    (void)fsync(fd); /* paranoia */
    close(fd);
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
	    fatal("Illegal line break in folder name", EC_IOERR);

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
	    fatal("word too long", EC_IOERR);
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

void sync_log_channel(const char *channel, const char *fmt, ...)
{
    va_list ap;
    const char *val;

    va_start(ap, fmt);
    val = va_format(fmt, ap);
    va_end(ap);

    sync_log_base(channel, val);
}

void sync_log(const char *fmt, ...)
{
    va_list ap;
    const char *val;
    const char *ch;

    va_start(ap, fmt);
    val = va_format(fmt, ap);
    va_end(ap);

    if (channel_base) {
	for (ch = channel_base; ch < channel_end; ch += strlen(ch) + 1) {
	    sync_log_base(ch, val);
	}
    }
    else {
	/* just the regular log path */
	sync_log_base(NULL, val);
    }
}

