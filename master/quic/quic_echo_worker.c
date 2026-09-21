/* quic_echo_worker.c - minimal dispatched QUIC service, for measuring
 * the dispatch layer itself.
 *
 * Echoes every datagram straight back, with no QUIC or TLS handling at
 * all, so a measurement against it reflects what master's dispatch and
 * relay paths cost and nothing else. That is the same shape the
 * Performance figures in docsrc/concepts/features/quic-dispatch.rst
 * were taken with.
 *
 * Reads the AF_UNIX socketpair service.c hands it on stdin, whose
 * datagrams carry a struct quic_relay_pkt_hdr in front. Replies go
 * out on the handoff's send_fd where master passed one.
 *
 * Not part of the build. To build it, add to Makefile.am:
 *
 *   libexec_PROGRAMS += master/quic/quic_echo_worker
 *   master_quic_quic_echo_worker_SOURCES = imap/mutex_fake.c \
 *       master/quic/quic_echo_worker.c $(imap_SERVICE_SOURCES)
 *   master_quic_quic_echo_worker_LDADD = $(LD_SERVER_ADD)
 */
#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "master/quic/quic_handoff.h"
#include "master/service.h"

#include "imap/global.h"

/* Big enough for any datagram plus the relay's own prefix. */
#define ECHO_BUFSIZE (QUIC_PKT_BUFSIZE + sizeof(struct quic_relay_pkt_hdr))

/* service.c and libcyrus_imap expect these from every service. */
const int config_need_data = 0;

EXPORTED void fatal(const char *msg, int code)
{
    syslog(LOG_ERR, "fatal: %s", msg);
    exit(code);
}

int service_init(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    return 0;
}

int service_main(int argc __attribute__((unused)),
                 char **argv __attribute__((unused)),
                 char **envp __attribute__((unused)))
{
    const struct quic_handoff *h = service_quic_handoff();
    uint8_t buf[ECHO_BUFSIZE];
    struct sockaddr_storage peer;
    socklen_t peerlen;
    bool relayed;
    int sendfd;
    ssize_t n;

    if (!h) return 0;

    /* An AF_UNIX fd means master is relaying to us, so arriving
     * datagrams carry a struct quic_relay_pkt_hdr. */
    {
        struct sockaddr_storage me;
        socklen_t melen = sizeof(me);

        if (getsockname(STDIN_FILENO, (struct sockaddr *) &me, &melen))
            return 0;
        relayed = (me.ss_family == AF_UNIX);
    }

    /* Outgoing goes straight to the client, on the socket master
     * passed us. */
    sendfd = service_quic_send_fd();
    if (sendfd < 0) sendfd = STDIN_FILENO;

    memcpy(&peer, &h->peer_addr, sizeof(peer));
    peerlen = h->peer_addrlen;

    /* master already read this connection's first datagram to dispatch
     * it, so echo that before touching the socket. */
    if (h->pktlen &&
        sendto(sendfd, h->pkt, h->pktlen, 0,
               (struct sockaddr *) &peer, peerlen) < 0) {
        return 0;
    }

    /* End the session on a long idle gap rather than waiting for
     * master, so workers return to the pool at the end of a run. Well
     * above the load generator's own 3s per-packet timeout: a shorter
     * one expires mid-sweep and looks like a dropped connection. */
    {
        struct timeval tv = { .tv_sec = 30 };

        setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* Then echo whatever else arrives, until the client goes quiet or
     * master tears the connection down under us. */
    while ((n = recv(STDIN_FILENO, buf, sizeof(buf), 0)) > 0) {
        const uint8_t *payload = buf;

        if (relayed) {
            struct quic_relay_pkt_hdr hdr;

            if (n < (ssize_t) sizeof(hdr)) break;
            memcpy(&hdr, buf, sizeof(hdr));
            memcpy(&peer, &hdr.peer, sizeof(peer));
            peerlen = hdr.peerlen;
            payload += sizeof(hdr);
            n -= (ssize_t) sizeof(hdr);
        }

        if (sendto(sendfd, payload, (size_t) n, 0,
                   (struct sockaddr *) &peer, peerlen) < 0) break;
    }

    return 0;
}

void service_abort(int error)
{
    exit(error);
}
