/* sync_log.c -- Cyrus synchonization logging functions
 *
 * Copyright (c) 1998-2005 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 * $Id: sync_log.c,v 1.1.2.2 2005/02/28 20:45:15 ken3 Exp $
 */

/* YYY Need better quoting for obscure filenames: use literals? */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <com_err.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "util.h"
#include "retry.h"
#include "append.h"
#include "sync_log.h"
#include "lock.h"

static const char *sync_log_file = NULL;
static const char *sync_dir      = NULL;

void sync_log_init(void)
{
    sync_log_file  = config_getstring(IMAPOPT_SYNC_LOG_FILE);
    sync_dir       = config_getstring(IMAPOPT_SYNC_DIR);
}

static void sync_log_base(const char *string, int len)
{
    int fd, rc;
    struct stat sbuffile, sbuffd;
    int retries = 0;

    if (!sync_log_file) return;

    while (retries++ < SYNC_LOG_RETRIES) {
        if ((fd = open(sync_log_file, O_WRONLY|O_APPEND|O_CREAT, 0640)) < 0) {
            syslog(LOG_ERR, "sync_log(): Unable to write to log file %s: %s",
                   sync_log_file, strerror(errno));
            return;
        }

        if (lock_blocking(fd) == -1) {
	    syslog(LOG_ERR, "sync_log(): Failed to lock %s for %s: %m",
		   sync_log_file, string);
            close(fd);
            return;
	}

        /* Check that the file wasn't renamed after it was opened above */
        if ((fstat(fd, &sbuffd) == 0) &&
            (stat(sync_log_file, &sbuffile) == 0) &&
            (sbuffd.st_ino == sbuffile.st_ino))
            break;

        close(fd);
    }
    if (retries >= SYNC_LOG_RETRIES) {
        close(fd);
        syslog(LOG_ERR,
               "sync_log(): Failed to lock %s for %s after %d attempts",
               sync_log_file, string, retries);
        return;
    }

    if ((rc = retry_write(fd, string, len)) < 0)
        syslog(LOG_ERR, "write() to %s failed: %s",
               sync_log_file, strerror(errno));

    if (rc < len)
        syslog(LOG_ERR, "Partial write to %s: %d out of %d only written",
               sync_log_file, rc, len);
    
    close(fd);
}

void sync_log_user(const char *user)
{
    char buf[64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "USER %s\n", user);

    sync_log_base(buf, len);
}

void sync_log_meta(const char *user)
{
    char buf[64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "META %s\n", user);

    sync_log_base(buf, len);
}

static const char *sync_quote_name(const char *name)
{
    static char buf[(2*MAX_MAILBOX_NAME)+3];
    const char *s;
    char *p = buf;
    char c;
    int  need_quote = 0;

    s = name;
    while ((c=*s++)) {
        if ((c == ' ') || (c == '\t') || (c == '\\') || (c == '\"') ||
            (c == '(') || (c == ')')  || (c == '{')  || (c == '}'))
            need_quote = 1;
        else if ((c == '\r') || (c == '\n'))
            fatal("Illegal line break in folder name", EC_IOERR);
    }

    if ((s-name) > MAX_MAILBOX_NAME+64)
        fatal("word too long", EC_IOERR);

    if (!need_quote) return(name);

    s = name;
    *p++ = '\"';
    while ((c=*s++)) {
        if ((c == '\\') || (c == '\"') || (c == '{') || (c == '}'))
            *p++ = '\\';
        *p++ = c;
    }

    *p++ = '\"';
    *p++ = '\0';
    
    return(buf);
}

void sync_log_mailbox(const char *name)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "MAILBOX %s\n", sync_quote_name(name));
    sync_log_base(buf, len);
}

/* Log two mailbox names as a single write() so they won't get separated
   by sync_client runner */

void sync_log_mailbox_double(const char *name1, const char *name2)
{
    char buf[(2*MAX_MAILBOX_NAME)+128];
    int len1, len2;

    if (!sync_log_file) return;

    len1 = snprintf(buf, sizeof(buf), "MAILBOX %s\n", sync_quote_name(name1));
    len2 = snprintf(buf+len1,
                    sizeof(buf)-len1, "MAILBOX %s\n", sync_quote_name(name2));

    sync_log_base(buf, len1+len2);
}

void sync_log_append(const char *name)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "APPEND %s\n", sync_quote_name(name));
    sync_log_base(buf, len);
}


void sync_log_acl(const char *name)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "ACL %s\n", sync_quote_name(name));
    sync_log_base(buf, len);
}


void sync_log_quota(const char *name)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!sync_log_file) return;

    len = snprintf(buf, sizeof(buf), "QUOTA %s\n", sync_quote_name(name));
    sync_log_base(buf, len);
}


void sync_log_seen(const char *user, const char *name)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!(sync_log_file && user && user[0])) return;

    len = snprintf(buf, sizeof(buf),
                   "SEEN %s %s\n", user, sync_quote_name(name));

    sync_log_base(buf, len);
}

void sync_log_subscribe(const char *user, const char *name, int add)
{
    char buf[MAX_MAILBOX_NAME+64];
    int len;

    if (!(sync_log_file && user && user[0])) return;

    len = snprintf(buf, sizeof(buf), "%s %s %s\n",
		   add ? "SUB" : "UNSUB", user, sync_quote_name(name));

    sync_log_base(buf, len);
}

int sync_log_lock(int *fdp, char *userid)
{
    char fnamebuf[MAX_MAILBOX_PATH+1];
    int r = 0;

    if (!sync_log_file) return (0);

    if (!sync_dir) return(IMAP_INTERNAL);

    snprintf(fnamebuf, sizeof(fnamebuf), "%s/locks/%s", sync_dir, userid);

    if ((*fdp = open(fnamebuf, O_CREAT|O_WRONLY, 0777)) < 0)
        return(IMAP_IOERROR);

    r = lock_blocking(*fdp);
    if (r == -1) {
        syslog(LOG_ERR, "IOERROR: locking sync for %s: %m", userid);
        return IMAP_IOERROR;
    }

    return (0);
}

int sync_log_unlock(int *fdp)
{
    if (!sync_log_file) return (0);

    if (!sync_dir) return(IMAP_INTERNAL);

    if (*fdp >= 0)
        close(*fdp);

    *fdp = -1;

    return(0);
}

