/* notify.c -- Module to notify of new mail
 * $Id: notify.c,v 1.6 2002/05/07 18:50:21 leg Exp $ 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

#include "imapconf.h"
#include "notify.h"

extern int errno;

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
	    int nopt, char **options,
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
	syslog(LOG_ERR, "unable to open notify socket(): %m");
	return;
    }

    memset((char *)&sun_data, 0, sizeof(sun_data));
    sun_data.sun_family = AF_UNIX;
    notify_sock = config_getstring("notifysocket", NULL);
    if (notify_sock) {	
	strcpy(sun_data.sun_path, notify_sock);
    }
    else {
	strcpy(sun_data.sun_path, config_dir);
	strcat(sun_data.sun_path, FNAME_NOTIFY_SOCK);
    }

    /*
     * build request of the form:
     *
     * method NUL class NUL priority NUL user NUL mailbox NUL
     *   nopt NUL N(option NUL) message NUL
     */

    r = add_arg(buf, NOTIFY_MAXSIZE, method, &buflen);
    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, class, &buflen);
    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, priority, &buflen);
    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, user, &buflen);
    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, mailbox, &buflen);

    sprintf(noptstr, "%d", nopt);
    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, noptstr, &buflen);

    for (i = 0; !r && i < nopt; i++) {
	r = add_arg(buf, NOTIFY_MAXSIZE, options[i], &buflen);
    }

    if (!r) r = add_arg(buf, NOTIFY_MAXSIZE, message, &buflen);

    if (r) {
        syslog(LOG_ERR, "notify datagram too large");
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
