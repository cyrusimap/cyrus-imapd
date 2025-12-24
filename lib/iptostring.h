/* iptostring.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef IPTOSTRING_H
#define IPTOSTRING_H

#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int iptostring(const struct sockaddr *addr, socklen_t addrlen,
               char *out, unsigned outlen);

#endif /* IPTOSTRING_H */
