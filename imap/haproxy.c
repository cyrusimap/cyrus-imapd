/* haproxy.c - HAProxy protocol functions.
 *
 * XXX  This code is mostly lifted directly from:
 *
 * https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "haproxy.h"

/* returns 0 on success, <0 upon error */
EXPORTED int haproxy_read_hdr(int s, struct sockaddr *to, struct sockaddr *from)
{
    static const char v2sig[] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

    union {
        struct {
            char line[108];
        } v1;
        struct {
            uint8_t sig[12];
            uint8_t ver_cmd;
            uint8_t fam;
            uint16_t len;
            union {
                struct {  /* for TCP/UDP over IPv4, len = 12 */
                    uint32_t src_addr;
                    uint32_t dst_addr;
                    uint16_t src_port;
                    uint16_t dst_port;
                } ip4;
                struct {  /* for TCP/UDP over IPv6, len = 36 */
                    uint8_t  src_addr[16];
                    uint8_t  dst_addr[16];
                    uint16_t src_port;
                    uint16_t dst_port;
                } ip6;
                struct {  /* for AF_UNIX sockets, len = 216 */
                    uint8_t src_addr[108];
                    uint8_t dst_addr[108];
                } unx;
            } addr;
        } v2;
    } hdr;

    int size, ret;

    do {
        ret = recv(s, &hdr, sizeof(hdr), MSG_PEEK);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        return -1;

    if (ret >= 16 && memcmp(&hdr.v2, v2sig, 12) == 0 &&
        (hdr.v2.ver_cmd & 0xF0) == 0x20) {
        size = 16 + ntohs(hdr.v2.len);
        if (ret < size)
            return -1; /* truncated or too large header */

        switch (hdr.v2.ver_cmd & 0xF) {
        case 0x01: /* PROXY command */
            switch (hdr.v2.fam) {
            case 0x11:  /* TCPv4 */
                ((struct sockaddr_in *) from)->sin_family = AF_INET;
                ((struct sockaddr_in *) from)->sin_addr.s_addr =
                    hdr.v2.addr.ip4.src_addr;
                ((struct sockaddr_in *) from)->sin_port =
                    hdr.v2.addr.ip4.src_port;
                ((struct sockaddr_in *) to)->sin_family = AF_INET;
                ((struct sockaddr_in *) to)->sin_addr.s_addr =
                    hdr.v2.addr.ip4.dst_addr;
                ((struct sockaddr_in *) to)->sin_port =
                    hdr.v2.addr.ip4.dst_port;
                goto done;
            case 0x21:  /* TCPv6 */
                ((struct sockaddr_in6 *) from)->sin6_family = AF_INET6;
                memcpy(&((struct sockaddr_in6 *) from)->sin6_addr,
                       hdr.v2.addr.ip6.src_addr, 16);
                ((struct sockaddr_in6 *) from)->sin6_port =
                    hdr.v2.addr.ip6.src_port;
                ((struct sockaddr_in6 *) to)->sin6_family = AF_INET6;
                memcpy(&((struct sockaddr_in6 *) to)->sin6_addr,
                       hdr.v2.addr.ip6.dst_addr, 16);
                ((struct sockaddr_in6 *) to)->sin6_port =
                    hdr.v2.addr.ip6.dst_port;
                goto done;
            }
            /* unsupported protocol, keep local connection address */
            break;
        case 0x00: /* LOCAL command */
            /* keep local connection address for LOCAL */
            break;
        default:
            return -1; /* not a supported command */
        }
    }
    else if (ret >= 8 && memcmp(hdr.v1.line, "PROXY", 5) == 0) {
        char *end = memchr(hdr.v1.line, '\r', ret - 1);
        if (!end || end[1] != '\n')
            return -1; /* partial or invalid header */
        *end = '\0'; /* terminate the string to ease parsing */
        size = end + 2 - hdr.v1.line; /* skip header + CRLF */
        /* parse the V1 header using favorite address parsers like inet_pton.
         * return -1 upon error, or simply fall through to accept.
         */
        char *proto = NULL, lipbuf[NI_MAXHOST], ripbuf[NI_MAXHOST];
        uint16_t lport, rport;
        int n = sscanf(hdr.v1.line, "PROXY %ms %s %s %hu %hu",
                       &proto, ripbuf, lipbuf, &rport, &lport);
        if (n >= 1 && !strcmp(proto, "UNKNOWN")) {
            ret = 1;
        }
        else if (n == 5 && !strcmp(proto, "TCP4")) {
            ((struct sockaddr_in *) from)->sin_family = AF_INET;
            ((struct sockaddr_in *) from)->sin_port = rport;
            ret = inet_pton(AF_INET, ripbuf,
                            &((struct sockaddr_in *) from)->sin_addr);
        }
        else if (n == 5 && !strcmp(proto, "TCP6")) {
            ((struct sockaddr_in6 *) from)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *) from)->sin6_port = rport;
            ret = inet_pton(AF_INET6, ripbuf,
                            &((struct sockaddr_in6 *) from)->sin6_addr);
        }
        else {
            ret = -1;
        }
        free(proto);

        if (ret != 1) {
            /* invalid header */
            return -1;
        }
    }
    else {
        /* Wrong protocol */
        return -1;
    }

 done:
    /* we need to consume the appropriate amount of data from the socket */
    do {
        ret = recv(s, &hdr, size, 0);
    } while (ret == -1 && errno == EINTR);

    return (ret != size ? -1 : 0);
}
