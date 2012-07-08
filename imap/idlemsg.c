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

#include "assert.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "idlemsg.h"
#include "global.h"

/* UNIX socket variables */
static int idle_sock = -1;
static struct sockaddr_un idle_local;

int idle_make_server_address(struct sockaddr_un *mysun)
{
    const char *idle_sock;

    memset(mysun, 0, sizeof(*mysun));
    mysun->sun_family = AF_UNIX;
    idle_sock = config_getstring(IMAPOPT_IDLESOCKET);
    if (idle_sock) {
	strlcpy(mysun->sun_path, idle_sock, sizeof(mysun->sun_path));
    }
    else {
	/* TODO: detect overflow and fail */
	strlcpy(mysun->sun_path, config_dir, sizeof(mysun->sun_path));
	strlcat(mysun->sun_path, FNAME_IDLE_SOCK, sizeof(mysun->sun_path));
    }
    return 1;
}

HIDDEN int idle_make_client_address(struct sockaddr_un *mysun)
{
    memset(mysun, 0, sizeof(*mysun));
    mysun->sun_family = AF_UNIX;
    /* TODO: detect overflow and fail */
    snprintf(mysun->sun_path, sizeof(mysun->sun_path), "%s%s/idle.%d",
	     config_dir, FNAME_IDLE_SOCK_DIR, (int)getpid());
    return 1;
}

/* Extract an identifying string from the remote AF_UNIX address,
 * suitable for logging debug messages.  Returns a string into an
 * internal buffer */
const char *idle_id_from_addr(const struct sockaddr_un *mysun)
{
    const char *tail = strrchr(mysun->sun_path, '/');
    const char *p;
    /* Has to be an absolute path, so there must be at least 1 / */
    assert(tail);
    tail++;
    p = strchr(tail, '.');
    return (p ? p+1 : tail);
}

int idle_init_sock(const struct sockaddr_un *local)
{
    int len;
    int s;
    mode_t oldumask;

    assert(idle_sock == -1);

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
	close(s);
	return 0;
    }
    umask(oldumask); /* for Linux */
    chmod(local->sun_path, 0777); /* for DUX */

    idle_sock = s;
    idle_local = *local;

    return 1;
}

void idle_done_sock(void)
{
    if (idle_sock >= 0) {
	close(idle_sock);
	unlink(idle_local.sun_path);
	memset(&idle_local, 0, sizeof(struct sockaddr_un)); 
    }

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
	syslog(LOG_ERR, "IDLE: error sending message: %s (%s)",
	       idle_msg_string(msg->which), msg->mboxname);
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
    memset(msg, 0, sizeof(idle_message_t));

    n = recvfrom(idle_sock, (void *) msg, sizeof(idle_message_t), 0,
		 (struct sockaddr *) remote, &remote_len);

    if (n < 0)
	return 0;

    if (n <= IDLE_MESSAGE_BASE_SIZE ||
	msg->mboxname[n - 1 - IDLE_MESSAGE_BASE_SIZE] != '\0') {
	syslog(LOG_ERR, "IDLE: invalid message received: size=%d, type=%s\n",
	       n, idle_msg_string(msg->which));
	return 0;
    }

    return 1;
}

const char *idle_msg_string(unsigned long which)
{
    const char *msg = "unknown";

    switch(which) {
    case IDLE_MSG_INIT:
	msg = "init";
	break;
    case IDLE_MSG_DONE:
	msg = "done";
	break;
    case IDLE_MSG_NOTIFY:
	msg = "notify";
	break;
    case IDLE_MSG_NOOP:
	msg = "noop";
	break;
    case IDLE_MSG_ALERT:
	msg = "alert";
	break;
    }

    return msg;
}

