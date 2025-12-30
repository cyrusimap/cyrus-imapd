/* iptostring.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "iptostring.h"

EXPORTED int iptostring(const struct sockaddr *addr, socklen_t addrlen,
               char *out, unsigned outlen) {
    char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
    int niflags;

    if(!addr || !out) {
        errno = EINVAL;
        return -1;
    }

    niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#ifdef NI_WITHSCOPEID
    if (addr->sa_family == AF_INET6)
        niflags |= NI_WITHSCOPEID;
#endif
    if (getnameinfo(addr, addrlen, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
                    niflags) != 0) {
        errno = EINVAL;
        return -1;
    }

    if(outlen < strlen(hbuf) + strlen(pbuf) + 2) {
        errno = ENOMEM;
        return -1;
    }

    snprintf(out, outlen, "%s;%s", hbuf, pbuf);

    return 0;
}
