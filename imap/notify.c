/* notify.c -- Module to notify of new mail
 $Id: notify.c,v 1.1 2002/03/21 21:10:03 ken3 Exp $
 
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
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "imapconf.h"
#include "retry.h"
#include "notify.h"

extern int errno;

#define FNAME_NOTIFY_SOCK "/socket/notify"

#define NOTIFY_MAXOPT 10

void notify(const char *method,
	    const char *class, const char *priority,
	    const char *user, const char *mailbox,
	    int nopt, char **options,
	    const char *message)
{
    const char *notify_sock;
    static char response[1024];
    int s;
    struct sockaddr_un srvaddr;
    int fdflags;
    int r;
    unsigned short count;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "unable to open notify socket(): %m");
	return;
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    notify_sock = config_getstring("notifysocket", NULL);
    if (notify_sock) {	
	strcpy(srvaddr.sun_path, notify_sock);
    }
    else {
	strcpy(srvaddr.sun_path, config_dir);
	strcat(srvaddr.sun_path, FNAME_NOTIFY_SOCK);
    }

    /* put us in non-blocking mode */
    fdflags = fcntl(s, F_GETFD, 0);
    if (fdflags != -1) fdflags = fcntl(s, F_SETFL, O_NONBLOCK | fdflags);
    if (fdflags == -1) { 
	syslog(LOG_ERR, 
	       "error setting notify socket to nonblocking: fcntl(): %m");
	close(s); 
	return; 
    }

    r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
    if (r == -1) {
	syslog(LOG_ERR, "unable to connect to notify socket(): %m");
	return;
    }

    /*
     * build request of the form:
     *
     * count method count class count priority count user count mailbox
     *   nopt N(count option) count message
     */
    {
	unsigned short n_len, c_len, p_len, u_len, m_len,
	    o_len[NOTIFY_MAXOPT], t_len;
 	struct iovec iov[13 + 2*NOTIFY_MAXOPT];
	int num_iov = 0;
	int i;

 	n_len = method ? htons(strlen(method)) : 0;
 	c_len = class ? htons(strlen(class)) : 0;
 	p_len = priority ? htons(strlen(priority)) : 0;
 	u_len = user ? htons(strlen(user)) : 0;
 	m_len = mailbox ? htons(strlen(mailbox)) : 0;
	count = htons((unsigned short) nopt);
	t_len = message ? htons(strlen(message)) : 0;

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &n_len, sizeof(n_len));
	if (method) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) method);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &c_len, sizeof(c_len));
	if (class) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) class);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &p_len, sizeof(p_len));
	if (priority) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) priority);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &u_len, sizeof(u_len));
	if (user) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) user);
	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &m_len, sizeof(m_len));
	if (mailbox) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) mailbox);

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &count, sizeof(count));

	for (i = 0; i < nopt; i++) {
	    o_len[i] = options[i] ? htons(strlen(options[i])) : 0;
	    WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &o_len[i],
				sizeof(o_len[i]));
	    if (options[i]) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, options[i]);
	}	    

	WRITEV_ADD_TO_IOVEC(iov, num_iov, (char*) &t_len, sizeof(t_len));
	if (message) WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, (char*) message);

	if (retry_writev(s, iov, num_iov) == -1) {
            syslog(LOG_ERR, "write to notifyd failed");
  	    return;
  	}
    }

    /*
     * read response of the form:
     *
     * count result
     */
    if (retry_read(s, &count, sizeof(count)) < (int) sizeof(count)) {
        syslog(LOG_ERR, "read size from notifyd\n");
	return;
    }
  
    count = ntohs(count);
    if (count < 2) { /* MUST have at least "OK" or "NO" */
	close(s);
        syslog(LOG_ERR, "bad response from notifyd");
	return;
    }
  
    count = (int)sizeof(response) < count ? sizeof(response) : count;
    if (retry_read(s, response, count) < count) {
	close(s);
        syslog(LOG_ERR, "read from notifyd failed");
	return;
    }
    response[count] = '\0';

    close(s);
  
    if (!strncmp(response, "NO", 2))
	syslog(LOG_ERR, "%s", response);
}
