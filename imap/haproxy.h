/* haproxy.h - Header for HAProxy protocol functions. */

#ifndef INCLUDED_HAPROXY_H
#define INCLUDED_HAPROXY_H

#include <sys/socket.h>

extern int haproxy_read_hdr(int s, struct sockaddr *to, struct sockaddr *from);

#endif /* INCLUDED_HAPROXY_H */
