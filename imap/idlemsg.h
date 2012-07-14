/* idled.h - daemon for handling IMAP IDLE notifications
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
 * $Id: idled.h,v 1.9 2010/01/06 17:01:32 murch Exp $
 */

#ifndef IDLEMSG_H
#define IDLEMSG_H

#include <sys/socket.h>
#include <sys/un.h>
#include "mailbox.h"

/* socket to communicate with the idled */
#define FNAME_IDLE_SOCK_DIR "/socket"
#define FNAME_IDLE_SOCK FNAME_IDLE_SOCK_DIR"/idle"

typedef struct idle_message_s idle_message_t;

struct idle_message_s
{
    unsigned long which;

    /* 1 for null. leave at end of structure for alignment */
    char mboxname[MAX_MAILBOX_BUFFER];
};

#define IDLE_MESSAGE_BASE_SIZE	(1 * (int) sizeof(unsigned long))

enum {
    IDLE_MSG_INIT,
    IDLE_MSG_DONE,
    IDLE_MSG_NOTIFY,
    IDLE_MSG_NOOP,
    IDLE_MSG_ALERT
};

int idle_make_server_address(struct sockaddr_un *);
int idle_make_client_address(struct sockaddr_un *);
const char *idle_id_from_addr(const struct sockaddr_un *);
int idle_init_sock(const struct sockaddr_un *);
void idle_done_sock(void);
int idle_get_sock(void);
int idle_send(const struct sockaddr_un *remote,
	      const idle_message_t *msg);
int idle_recv(struct sockaddr_un *remote, idle_message_t *msg);
const char *idle_msg_string(unsigned long which);


#endif
