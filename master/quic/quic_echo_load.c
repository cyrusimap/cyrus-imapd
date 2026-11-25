/* quic_echo_load.c - load generator for quic_echo_worker.c, for
 * measuring master's QUIC dispatch backends */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*
 * quic_echo_load [-n conns] [-c concurrent] [-k packets] [-s size]
 *                [-t timeout_ms] [-r] host port
 *
 * Opens conns connections in all, concurrent at a time, each from its
 * own UDP socket.  A connection sends a 1200-byte QUIC v1 Initial, which
 * master dispatches to a worker, then packets short-header packets of
 * size bytes addressed to its own Destination Connection ID, one at a
 * time, each echoed back by quic_echo_worker.  It reports the latency of
 * the Initial's echo (dispatch, including any fork) and of the
 * short-header ones (the per-packet path) separately.
 *
 * Not real QUIC: nothing is encrypted, and only the headers QUIC
 * dispatch reads are well formed.  A packet with no echo within
 * timeout_ms (default 3000, under quic_echo_worker's 30s idle timeout)
 * counts as lost and ends its connection.
 *
 * quic_echo_worker keeps a session until it has been idle for 30s, so
 * by default every connection gets a newly forked worker.  With -r a
 * connection's last packet tells the worker to end its session once
 * echoed, so the worker returns to the pool for a later connection to
 * reuse; -r needs -k 1 or more.
 *
 * Not part of the build:
 *
 *   cc -O2 -Wall -o quic_echo_load master/quic/quic_echo_load.c
 */

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CIDLEN        8
#define INITIAL_SIZE  1200
#define MAX_PKT       1500
#define ECHO_END      0x7f      /* as in quic_echo_worker.c */

struct conn {
    int sock;
    uint8_t dcid[CIDLEN];
    int sent;                   /* packets sent: the Initial, then shorts */
    uint8_t pkt[MAX_PKT];       /* the packet awaiting its echo */
    size_t pktlen;
    double sent_at;             /* ms */
};

struct samples {
    double *v;
    size_t n, cap;
};

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void add(struct samples *s, double v)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? 2 * s->cap : 1024;
        s->v = realloc(s->v, s->cap * sizeof(double));
        if (!s->v) {
            perror("realloc");
            exit(1);
        }
    }
    s->v[s->n++] = v;
}

static int cmp(const void *a, const void *b)
{
    double x = *(const double *) a, y = *(const double *) b;

    return (x > y) - (x < y);
}

static void report(const char *what, struct samples *s)
{
    if (!s->n) {
        printf("%-12s none\n", what);
        return;
    }
    qsort(s->v, s->n, sizeof(double), cmp);
    printf("%-12s n=%zu p50=%.2f p95=%.2f p99=%.2f max=%.2f ms\n", what,
           s->n, s->v[s->n / 2], s->v[s->n * 95 / 100],
           s->v[s->n * 99 / 100], s->v[s->n - 1]);
}

static void fill_random(void *buf, size_t len)
{
    if (getrandom(buf, len, 0) != (ssize_t) len) {
        perror("getrandom");
        exit(1);
    }
}

/* The next packet for c: its Initial, or a short-header packet, the
 * last of which ends the worker's session if end is set */
static void build_packet(struct conn *c, size_t short_size, bool end)
{
    uint8_t *p = c->pkt;

    if (!c->sent) {
        uint8_t scid[CIDLEN];

        fill_random(scid, sizeof(scid));
        *p++ = 0xc0;                            /* long header, Initial */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1; /* QUIC v1 */
        *p++ = CIDLEN;
        memcpy(p, c->dcid, CIDLEN);
        p += CIDLEN;
        *p++ = CIDLEN;
        memcpy(p, scid, CIDLEN);
        p += CIDLEN;
        *p++ = 0;                               /* token length */
        c->pktlen = INITIAL_SIZE;
        /* length (2-byte varint), then the rest */
        size_t rest = INITIAL_SIZE - (p - c->pkt) - 2;
        *p++ = 0x40 | (rest >> 8);
        *p++ = rest & 0xff;
        fill_random(p, rest);
    }
    else {
        *p++ = end ? ECHO_END : 0x40;           /* short header */
        memcpy(p, c->dcid, CIDLEN);
        p += CIDLEN;
        c->pktlen = short_size;
        fill_random(p, short_size - (p - c->pkt));
    }
}

static bool reuse;
static int packets = 10;

static int send_next(struct conn *c, size_t short_size)
{
    build_packet(c, short_size, reuse && c->sent == packets);
    c->sent_at = now_ms();
    c->sent++;
    return send(c->sock, c->pkt, c->pktlen, 0) == (ssize_t) c->pktlen
           ? 0 : -1;
}

static int open_conn(struct conn *c, const struct addrinfo *ai, int ep)
{
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = c };

    memset(c, 0, sizeof(*c));
    c->sock = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (c->sock < 0 || connect(c->sock, ai->ai_addr, ai->ai_addrlen) ||
        epoll_ctl(ep, EPOLL_CTL_ADD, c->sock, &ev)) {
        perror("socket");
        exit(1);
    }
    fill_random(c->dcid, sizeof(c->dcid));
    return 0;
}

static void close_conn(struct conn *c)
{
    close(c->sock);
    c->sock = -1;
}

int main(int argc, char **argv)
{
    int nconns = 300, concurrent = 50, timeout_ms = 3000;
    size_t short_size = 100;
    struct addrinfo hints = { .ai_socktype = SOCK_DGRAM }, *ai;
    struct samples first = { 0 }, steady = { 0 };
    int opt, rv, started = 0, active = 0, ok = 0, lost = 0, ep;
    struct conn *conns;
    double t0;

    while ((opt = getopt(argc, argv, "n:c:k:s:t:r")) != -1) {
        switch (opt) {
        case 'n': nconns = atoi(optarg); break;
        case 'c': concurrent = atoi(optarg); break;
        case 'k': packets = atoi(optarg); break;
        case 's': short_size = (size_t) atoi(optarg); break;
        case 't': timeout_ms = atoi(optarg); break;
        case 'r': reuse = true; break;
        default:
            fprintf(stderr, "usage: quic_echo_load [-n conns] [-c concurrent]"
                            " [-k packets] [-s size] [-t timeout_ms]"
                            " [-r] host port\n");
            return 1;
        }
    }
    if (argc - optind != 2 || nconns < 1 || concurrent < 1 || packets < (reuse ? 1 : 0) ||
        short_size < 1 + CIDLEN || short_size > MAX_PKT) {
        fprintf(stderr, "quic_echo_load: bad arguments\n");
        return 1;
    }
    if ((rv = getaddrinfo(argv[optind], argv[optind + 1], &hints, &ai))) {
        fprintf(stderr, "quic_echo_load: %s\n", gai_strerror(rv));
        return 1;
    }
    if (concurrent > nconns) concurrent = nconns;

    conns = calloc(concurrent, sizeof(*conns));
    ep = epoll_create1(0);
    if (!conns || ep < 0) {
        perror("setup");
        return 1;
    }

    t0 = now_ms();
    for (int i = 0; i < concurrent; i++) {
        open_conn(&conns[i], ai, ep);
        send_next(&conns[i], short_size);
        started++;
        active++;
    }

    while (active) {
        struct epoll_event evs[64];
        double now;
        int n = epoll_wait(ep, evs, 64, 50);

        for (int i = 0; i < n; i++) {
            struct conn *c = evs[i].data.ptr;
            uint8_t buf[MAX_PKT];
            ssize_t len = recv(c->sock, buf, sizeof(buf), MSG_DONTWAIT);

            /* An echo is our own packet back; anything else is noise */
            if (c->sock < 0 || len != (ssize_t) c->pktlen ||
                memcmp(buf, c->pkt, c->pktlen)) {
                continue;
            }

            add(c->sent == 1 ? &first : &steady, now_ms() - c->sent_at);
            if (c->sent <= packets) {
                if (send_next(c, short_size)) {
                    lost++;
                    goto done;
                }
                continue;
            }
            ok++;
          done:
            close_conn(c);
            if (started < nconns) {
                open_conn(c, ai, ep);
                send_next(c, short_size);
                started++;
            }
            else {
                active--;
            }
        }

        /* A packet with no echo in time is lost, and so is its
         * connection */
        now = now_ms();
        for (int i = 0; i < concurrent; i++) {
            struct conn *c = &conns[i];

            if (c->sock < 0 || now - c->sent_at < timeout_ms) continue;
            lost++;
            close_conn(c);
            if (started < nconns) {
                open_conn(c, ai, ep);
                send_next(c, short_size);
                started++;
            }
            else {
                active--;
            }
        }
    }

    double secs = (now_ms() - t0) / 1e3;
    printf("connections  %d ok, %d lost, %.2fs, %.0f echoes/s\n", ok, lost,
           secs, (first.n + steady.n) / secs);
    report("first", &first);
    report("steady", &steady);

    freeaddrinfo(ai);
    return lost ? 3 : 0;
}
