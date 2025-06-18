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
 */

#ifndef IDLEMSG_H
#define IDLEMSG_H

#include <sys/socket.h>
#include <sys/un.h>

#include "json_support.h"

/* socket to communicate with the idled */
#define FNAME_IDLE_SOCK_DIR "/socket"
#define FNAME_IDLE_SOCK FNAME_IDLE_SOCK_DIR"/idle"

int idle_make_server_address(struct sockaddr_un *);
int idle_make_client_address(struct sockaddr_un *);
const char *idle_id_from_addr(const struct sockaddr_un *);
int idle_init_sock(const struct sockaddr_un *);
void idle_done_sock(void);
int idle_get_sock(void);
int idle_send(const struct sockaddr_un *remote, json_t *msg);
json_t *idle_recv(struct sockaddr_un *remote);
const char *idle_msg_get_mboxid(json_t *msg);

#endif /* IDLEMSG_H */
