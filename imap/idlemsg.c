/*
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
 *
 * $Id: idle.c,v 1.7 2010/01/06 17:01:32 murch Exp $
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <string.h>

#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "idlemsg.h"
#include "global.h"

/* UNIX socket variables */
static int idle_sock = -1;

int idle_make_server_address(struct sockaddr_un *sun)
{
    const char *idle_sock;

    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;
    idle_sock = config_getstring(IMAPOPT_IDLESOCKET);
    if (idle_sock) {
	strlcpy(sun->sun_path, idle_sock, sizeof(sun->sun_path));
    }
    else {
	/* TODO: detect overflow and fail */
	strlcpy(sun->sun_path, config_dir, sizeof(sun->sun_path));
	strlcat(sun->sun_path, FNAME_IDLE_SOCK, sizeof(sun->sun_path));
    }
    return 1;
}


int idle_make_client_address(struct sockaddr_un *sun)
{
    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_UNIX;
    /* TODO: detect overflow and fail */
    snprintf(sun->sun_path, sizeof(sun->sun_path), "%s%s/idle.%d",
	     config_dir, FNAME_IDLE_SOCK_DIR, (int)getpid());
    return 1;
}


int idle_init_sock(const struct sockaddr_un *local)
{
    int len;
    int s;
    mode_t oldumask;

    /* create socket we are going to use for listening */
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	return 0;
    }

    /* bind it to a local file */
    unlink(local->sun_path);
    len = sizeof(local->sun_family) + strlen(local->sun_path) + 1;

    oldumask = umask((mode_t) 0); /* for Linux */

    if (bind(s, (struct sockaddr *)local, len) == -1) {
	perror("bind");
	return 0;
    }
    umask(oldumask); /* for Linux */
    chmod(local->sun_path, 0777); /* for DUX */

    idle_sock = s;

    return 1;
}

void idle_done_sock(void)
{
    if (idle_sock >= 0)
	close(idle_sock);
    idle_sock = -1;
}

int idle_get_sock(void)
{
    return idle_sock;
}

/*
 * Send a message to idled
 */
int idle_send(const struct sockaddr_un *remote,
	      const idle_message_t *msg)
{
    if (idle_sock < 0)
	return 0;

    if (sendto(idle_sock, (void *) msg,
	       IDLE_MESSAGE_BASE_SIZE+strlen(msg->mboxname)+1, /* 1 for NULL */
	       0, (struct sockaddr *) remote, sizeof(*remote)) == -1) {
	syslog(LOG_ERR, "error sending to idled: %lx", msg->which);
	return 0;
    }

    return 1;
}

int idle_recv(struct sockaddr_un *remote, idle_message_t *msg)
{
    socklen_t remote_len = sizeof(*remote);
    int n;

    if (idle_sock < 0)
	return 0;

    memset(remote, 0, remote_len);
    n = recvfrom(idle_sock, (void *) msg, sizeof(idle_message_t), 0,
		 (struct sockaddr *) remote, &remote_len);

    if (n < 0)
	return 0;

    if (n <= IDLE_MESSAGE_BASE_SIZE ||
	msg->mboxname[n - 1 - IDLE_MESSAGE_BASE_SIZE] != '\0') {
	syslog(LOG_ERR, "Invalid message received, size=%d\n", n);
	return 0;
    }

    return 1;
}

