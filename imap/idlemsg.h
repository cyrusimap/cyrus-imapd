/* idled.h - daemon for handling IMAP IDLE notifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
