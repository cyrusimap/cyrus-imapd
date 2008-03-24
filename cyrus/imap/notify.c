/* notify.c -- Module to notify of new mail
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
 * $Id: notify.c,v 1.16 2008/03/24 17:09:18 murch Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "global.h"
#include "notify.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#define FNAME_NOTIFY_SOCK "/socket/notify"

#define NOTIFY_MAXSIZE 8192

static int add_arg(char *buf, int max_size, const char *arg, int *buflen)
{
    const char *myarg = (arg ? arg : "");
    int len = strlen(myarg) + 1;

    if (*buflen + len > max_size) return -1;

    strcat(buf+*buflen, myarg);
    *buflen += len;

    return 0;
}

void notify(const char *method,
	    const char *class, const char *priority,
	    const char *user, const char *mailbox,
	    int nopt, const char **options,
	    const char *message)
{
    const char *notify_sock;
    int soc;
    struct sockaddr_un sun_data;
    char buf[NOTIFY_MAXSIZE] = "", noptstr[20];
    int buflen = 0;
    int i, r = 0;

    soc = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (soc == -1) {
	syslog(LOG_ERR, "unable to create notify socket(): %m");
	return;
    }

    memset((char *)&sun_data, 0, sizeof(sun_data));
    sun_data.sun_family = AF_UNIX;
    notify_sock = config_getstring(IMAPOPT_NOTIFYSOCKET);
    if (notify_sock) {	
	strlcpy(sun_data.sun_path, notify_sock, sizeof(sun_data.sun_path));
    }
    else {
	strlcpy(sun_data.sun_path, config_dir, sizeof(sun_data.sun_path));
	strlcat(sun_data.sun_path,
		FNAME_NOTIFY_SOCK, sizeof(sun_data.sun_path));
    }

    /*
     * build request of the form:
     *
     * method NUL class NUL priority NUL user NUL mailbox NUL
     *   nopt NUL N(option NUL) message NUL
     */

    r = add_arg(buf, sizeof(buf), method, &buflen);
    if (!r) r = add_arg(buf, sizeof(buf), class, &buflen);
    if (!r) r = add_arg(buf, sizeof(buf), priority, &buflen);
    if (!r) r = add_arg(buf, sizeof(buf), user, &buflen);
    if (!r) r = add_arg(buf, sizeof(buf), mailbox, &buflen);

    snprintf(noptstr, sizeof(noptstr), "%d", nopt);
    if (!r) r = add_arg(buf, sizeof(buf), noptstr, &buflen);

    for (i = 0; !r && i < nopt; i++) {
	r = add_arg(buf, sizeof(buf), options[i], &buflen);
    }

    if (!r) r = add_arg(buf, sizeof(buf), message, &buflen);

    if (r) {
        syslog(LOG_ERR, "notify datagram too large, %s, %s",
	       user, mailbox);
	close(soc);
	return;
    }

    r = sendto(soc, buf, buflen, 0,
	       (struct sockaddr *)&sun_data, sizeof(sun_data));
    if (r < buflen) {
	syslog(LOG_ERR, "unable to sendto() notify socket: %m");
	return;
    }

    close(soc);

    return;
}
