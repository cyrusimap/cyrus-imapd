/* Standalone smoke test for master/quic/quic_handoff.c -- passing a
 * connection fd, and optionally a separate send socket, to a forked
 * worker, and sending from that socket. Not part of the build -- ad
 * hoc verification only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "master/quic/quic_handoff.h"

struct quic_handoff quic_handoff;

static int npass = 0, nfail = 0;

/* lib/xmalloc.c and friends call this on unrecoverable errors */
void fatal(const char *msg, int code)
{
    fprintf(stderr, "fatal: %s\n", msg);
    exit(code);
}

static void check(int cond, const char *what)
{
    printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
    cond ? npass++ : nfail++;
}

/* Bind a UDP socket to an ephemeral port on loopback and report the
 * address it actually got. */
static int bind_loopback(struct sockaddr_in *out)
{
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s < 0 || bind(s, (struct sockaddr *) &addr, sizeof(addr)) ||
        getsockname(s, (struct sockaddr *) &addr, &len)) {
        perror("bind_loopback");
        exit(1);
    }
    *out = addr;
    return s;
}

/* The worker half: take one handoff, report what came with it, and
 * reply to the client on whichever fd the handoff says to use. */
static void child(int hfd)
{
    struct quic_handoff h;
    int fd, sendfd;

    if (quic_recv_handoff(hfd, &h)) _exit(10);
    fd = h.recv_fd;

    /* Two fds means they must be distinct descriptors, not the same
     * number handed over twice. */
    if (h.send_fd >= 0 && h.send_fd == fd) _exit(11);

    sendfd = h.send_fd >= 0 ? h.send_fd : fd;
    if (sendto(sendfd, "pong", 4, 0, (struct sockaddr *) &h.peer_addr,
               h.peer_addrlen) != 4) _exit(12);

    _exit(h.send_fd >= 0 ? 0 : 1);
}

int main(void)
{
    struct sockaddr_in raddr, caddr, from;
    int rendez = bind_loopback(&raddr);
    int client = bind_loopback(&caddr);
    struct timeval tv = { .tv_sec = 2 };
    socklen_t fromlen;
    char buf[64];
    int hv[2], sv[2], status;
    pid_t pid;

    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* --- relay backend shape: connection socketpair + send socket --- */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hv) ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv)) {
        perror("socketpair");
        return 1;
    }

    memset(&quic_handoff, 0, sizeof(quic_handoff));
    memcpy(&quic_handoff.peer_addr, &caddr, sizeof(caddr));
    quic_handoff.peer_addrlen = sizeof(caddr);
    quic_handoff.recv_fd = sv[1];
    quic_handoff.send_fd = rendez;

    pid = fork();
    if (!pid) {
        close(hv[0]);
        child(hv[1]);
    }
    close(hv[1]);

    check(quic_send_handoff(hv[0], &quic_handoff) == 0,
          "quic_send_handoff passes a connection fd and a send socket");

    fromlen = sizeof(from);
    memset(buf, 0, sizeof(buf));
    check(recvfrom(client, buf, sizeof(buf), 0, (struct sockaddr *) &from,
                   &fromlen) == 4 && !memcmp(buf, "pong", 4),
          "client received what the worker sent on the passed socket");

    /* The whole point of passing the rendezvous socket rather than a
     * fresh one: the client sees the reply coming from the address it
     * addressed, so the QUIC connection stays intact. */
    check(from.sin_addr.s_addr == raddr.sin_addr.s_addr &&
          from.sin_port == raddr.sin_port,
          "reply's source address is the rendezvous socket's, not a new one");

    waitpid(pid, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "worker got a send_fd distinct from its connection fd");

    close(hv[0]);
    close(sv[0]);
    close(sv[1]);

    /* --- eBPF backend shape: one real socket, no separate send fd --- */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hv)) {
        perror("socketpair");
        return 1;
    }

    /* Stands in for the eBPF backend's per-connection UDP socket: the
     * worker both receives and sends on this one. */
    struct sockaddr_in conn_addr;
    int connsock = bind_loopback(&conn_addr);

    quic_handoff.recv_fd = connsock;
    quic_handoff.send_fd = -1;

    pid = fork();
    if (!pid) {
        close(hv[0]);
        child(hv[1]);
    }
    close(hv[1]);

    check(quic_send_handoff(hv[0], &quic_handoff) == 0,
          "quic_send_handoff passes a connection fd alone");

    fromlen = sizeof(from);
    memset(buf, 0, sizeof(buf));
    check(recvfrom(client, buf, sizeof(buf), 0, (struct sockaddr *) &from,
                   &fromlen) == 4 && !memcmp(buf, "pong", 4),
          "client received what the worker sent on the connection fd");
    check(from.sin_port == conn_addr.sin_port,
          "that reply came from the connection socket");

    waitpid(pid, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 1,
          "worker saw send_fd == -1 and fell back to the connection fd");

    printf("%d passed, %d failed\n", npass, nfail);
    return nfail ? 1 : 0;
}
