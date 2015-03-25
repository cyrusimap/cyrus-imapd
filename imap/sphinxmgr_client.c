/* sphinxmgr_client.c - client for talking to the cyr_sphinxmgr daemon
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
#include <sys/un.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "imap_err.h"
#include "global.h"
#include "retry.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

static int sphinxmgr_request(const char *req, size_t reqsize,
			     char *reply, size_t maxreply)
{
    const char *sockname = config_getstring(IMAPOPT_SPHINXMGR_SOCKET);
    struct sockaddr_un asun;
    int r;
    int s = -1;

    memset(&asun, 0, sizeof(asun));
    asun.sun_family = AF_UNIX;
    strlcpy(asun.sun_path, sockname, sizeof(asun.sun_path));

    s = socket(PF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
	syslog(LOG_ERR, "socket(PF_UNIX): %m");
	r = IMAP_IOERROR;
	goto out;
    }

    r = connect(s, (struct sockaddr *)&asun, sizeof(asun));
    if (r < 0) {
	syslog(LOG_ERR, "connect to %s failed: %m", sockname);
	r = IMAP_IOERROR;
	goto out;
    }

    r = retry_write(s, req, reqsize);
    if (r < 0) {
	syslog(LOG_ERR, "write to %s failed: %m", sockname);
	r = IMAP_IOERROR;
	goto out;
    }

    r = read(s, reply, maxreply-1);
    if (r < 0) {
	syslog(LOG_ERR, "read from %s failed: %m", sockname);
	r = IMAP_IOERROR;
	goto out;
    }
    reply[r] = '\0';
    r = 0;

out:
    if (s >= 0) close(s);
    return r;
}

int sphinxmgr_getsock(const char *mboxname, char **socknamep)
{
    int r;
    char *p;
    char buf[1024];

    snprintf(buf, sizeof(buf),  "GETSOCK %s\n", mboxname);
    r = sphinxmgr_request(buf, strlen(buf), buf, sizeof(buf));
    if (r) return r;
    if (strncmp(buf, "OK ", 3)) {
	syslog(LOG_ERR, "sphinxmgr returned failure: %s", buf);
	return IMAP_IOERROR;
    }
    p = strpbrk(buf+3, " \t\n\r");
    if (p) *p = '\0';
    *socknamep = xstrdup(buf+3);
    return 0;
}

int sphinxmgr_getconf(const char *mboxname, char **configp)
{
    int r;
    char *p;
    char buf[1024];

    snprintf(buf, sizeof(buf),  "GETCONF %s\n", mboxname);
    r = sphinxmgr_request(buf, strlen(buf), buf, sizeof(buf));
    if (r) return r;
    if (strncmp(buf, "OK ", 3)) {
	syslog(LOG_ERR, "sphinxmgr returned failure: %s", buf);
	return IMAP_IOERROR;
    }
    p = strpbrk(buf+3, " \t\n\r");
    if (p) *p = '\0';
    *configp = xstrdup(buf+3);
    return 0;
}

int sphinxmgr_stop(const char *mboxname)
{
    int r;
    char buf[1024];

    snprintf(buf, sizeof(buf),  "STOP %s\n", mboxname);
    r = sphinxmgr_request(buf, strlen(buf), buf, sizeof(buf));
    if (r) return r;
    if (strncmp(buf, "OK ", 3)) {
	syslog(LOG_ERR, "sphinxmgr returned failure: %s", buf);
	return IMAP_IOERROR;
    }
    return 0;
}

