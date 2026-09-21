/* Standalone smoke test for master/quic/quic_relay.c -- registration,
 * aliasing, forwarding (including migration), and EOF-driven teardown.
 * Not part of the build -- ad hoc verification only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <netinet/in.h>

#include "master/quic/quic_relay.h"

/* lib/xmalloc.c and friends call this on unrecoverable errors; every
 * real program (master.c included) supplies its own, so this test
 * must too. */
void fatal(const char *msg, int code)
{
    fprintf(stderr, "fatal: %s\n", msg);
    exit(code);
}

static int npass = 0, nfail = 0;

static void check(int cond, const char *what)
{
    if (cond) {
        printf("PASS: %s\n", what);
        npass++;
    }
    else {
        printf("FAIL: %s\n", what);
        nfail++;
    }
}

/* Forward pkt (addressed to cid, arriving from *from) to the worker
 * end sv1, then read it back and confirm: quic_relay_forward()
 * reported it as routed, the struct quic_relay_pkt_hdr prefix reports
 * *from correctly, and the payload after it matches pkt exactly. */
static void forward_and_check(const uint8_t *cid, uint8_t cidlen,
                              const unsigned char *pkt, size_t pktlen,
                              struct sockaddr_in *from, int sv1,
                              const char *label)
{
    struct sockaddr_storage peer;
    unsigned char buf[256];
    char label_buf[160];
    ssize_t n;

    memcpy(&peer, from, sizeof(*from));

    snprintf(label_buf, sizeof(label_buf),
            "%s: quic_relay_forward routes it", label);
    check(quic_relay_forward(cid, cidlen, pkt, pktlen,
                            &peer, sizeof(*from)),
         label_buf);

    n = recv(sv1, buf, sizeof(buf), 0);
    snprintf(label_buf, sizeof(label_buf),
            "%s: worker received hdr+payload of the right size", label);
    check(n == (ssize_t) (sizeof(struct quic_relay_pkt_hdr) + pktlen),
         label_buf);
    if (n < (ssize_t) sizeof(struct quic_relay_pkt_hdr)) return;

    struct quic_relay_pkt_hdr hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    struct sockaddr_in *hdr_addr = (struct sockaddr_in *) &hdr.peer;

    snprintf(label_buf, sizeof(label_buf),
            "%s: hdr reports the correct source port", label);
    check(hdr.peerlen == sizeof(*from) &&
         hdr_addr->sin_port == from->sin_port,
         label_buf);

    snprintf(label_buf, sizeof(label_buf),
            "%s: payload after the header matches what was sent", label);
    check((size_t) (n - (ssize_t) sizeof(hdr)) == pktlen &&
         !memcmp(buf + sizeof(hdr), pkt, pktlen),
         label_buf);
}

int main(void)
{
    quic_relay_init();

    /* Stands in for the real remote QUIC client, pre-migration. */
    int client1 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in c1addr = { .sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(client1, (struct sockaddr *) &c1addr, sizeof(c1addr));
    socklen_t c1len = sizeof(c1addr);
    getsockname(client1, (struct sockaddr *) &c1addr, &c1len);

    /* A second source address/port -- stands in for the same client
     * having migrated. */
    int client2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in c2addr = { .sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(client2, (struct sockaddr *) &c2addr, sizeof(c2addr));
    socklen_t c2len = sizeof(c2addr);
    getsockname(client2, (struct sockaddr *) &c2addr, &c2len);

    struct sockaddr_storage peer1;
    memcpy(&peer1, &c1addr, c1len);

    /* master/worker socketpair: sv[0] stays with "master" (this
     * test), sv[1] stands in for the worker's end (what
     * quic_send_handoff() would hand off in the real code). */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv)) {
        perror("socketpair"); return 1;
    }

    /* A CID pool: cids[0] is the primary, cids[1..] register as
     * aliases below (mirroring cid_pool[1..] in master.c), and dcid is
     * an additional alias for the client's original connection-attempt
     * DCID, exactly as quic_dispatch_connection() registers it. */
#define TEST_POOL_SIZE 4
    uint8_t cids[TEST_POOL_SIZE][QUIC_CIDLEN] = {
        { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 },
        { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xf0, 0x0d },
        { 0xf0, 0x0d, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef },
    };
    uint8_t dcid[QUIC_CIDLEN] =
        { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02 };
    uint8_t unknown_cid[QUIC_CIDLEN] = { 0 };

    check(quic_relay_add_conn(cids[0], sv[0], &peer1, c1len) == 0,
         "quic_relay_add_conn registers the primary CID");
    check(quic_relay_add_conn(cids[0], sv[0], &peer1, c1len) == -1,
         "quic_relay_add_conn rejects a duplicate primary CID");

    /* Nothing caps how high sock may be: master doesn't put these fds
     * in an fd_set, so FD_SETSIZE doesn't bound how many connections
     * it can carry. */
    {
        uint8_t hi_cid[QUIC_CIDLEN] =
            { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
        int sv3[2] = { -1, -1 };
        int hi = -1;

        if (!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv3))
            hi = dup2(sv3[0], FD_SETSIZE + 1);

        if (hi >= 0) {
            check(quic_relay_add_conn(hi_cid, hi, &peer1, c1len) == 0,
                 "quic_relay_add_conn accepts an fd past FD_SETSIZE");
            quic_relay_del_conn(hi_cid);
        }
        else {
            printf("SKIP: can't reach fd %d\n", FD_SETSIZE + 1);
        }
        if (sv3[0] >= 0) { close(sv3[0]); close(sv3[1]); }
    }

    for (int i = 1; i < TEST_POOL_SIZE; i++) {
        char what[64];
        snprintf(what, sizeof(what),
                "quic_relay_add_alias registers pool CID %d", i);
        check(quic_relay_add_alias(cids[0], cids[i]) == 0, what);
    }
    check(quic_relay_add_alias(cids[0], dcid) == 0,
         "quic_relay_add_alias registers the client's original dcid too");
    check(quic_relay_add_alias(cids[0], dcid) == -1,
         "quic_relay_add_alias rejects a duplicate alias");

    struct timeval tv = { .tv_usec = 200000 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client1, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char pkt[16] = "clienttoworker!!";

    forward_and_check(cids[0], sizeof(cids[0]), pkt, sizeof(pkt),
                      &c1addr, sv[1], "primary CID, pre-migration");
    forward_and_check(cids[2], sizeof(cids[2]), pkt, sizeof(pkt),
                      &c1addr, sv[1], "spare pool CID, pre-migration");
    forward_and_check(dcid, sizeof(dcid), pkt, sizeof(pkt),
                      &c1addr, sv[1], "original dcid alias, pre-migration");

    /* Now simulate migration: same primary CID, but arriving from
     * client2's address -- quic_relay_forward()'s own peer-tracking
     * should pick this up, and the header handed to the worker should
     * reflect it. */
    forward_and_check(cids[0], sizeof(cids[0]), pkt, sizeof(pkt),
                      &c2addr, sv[1], "primary CID, post-migration source");
    forward_and_check(cids[3], sizeof(cids[3]), pkt, sizeof(pkt),
                      &c2addr, sv[1],
                      "spare pool CID, post-migration source");

    check(!quic_relay_forward(unknown_cid, sizeof(unknown_cid), pkt,
                              sizeof(pkt), &peer1, c1len),
         "quic_relay_forward returns false for an unregistered cid");

    /* A second, throwaway connection, to confirm the alias-array cap
     * (QUIC_CID_POOL_SIZE) actually rejects overflow rather than
     * silently corrupting memory. */
    {
        int sv2[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv2)) {
            perror("socketpair"); return 1;
        }

        uint8_t primary2[QUIC_CIDLEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        check(quic_relay_add_conn(primary2, sv2[0], &peer1, c1len) == 0,
             "second connection: primary registers");

        int i, failed_early = 0;
        for (i = 0; i < 32; i++) {
            uint8_t alias2[QUIC_CIDLEN] = { 0xf0, 0, 0, 0, 0, 0, 0,
                                                 (uint8_t) i };
            if (quic_relay_add_alias(primary2, alias2)) {
                failed_early = 1;
                break;
            }
        }
        check(failed_early && i > 0,
             "alias-array cap rejects overflow instead of corrupting memory");

        quic_relay_del_conn(primary2);   /* also closes sv2[0] */
        close(sv2[1]);
    }

    /* Teardown: master unregisters the connection when the worker
     * reports idle or is reaped (quic_centry_clear_cids() in
     * master.c). Deleting the primary must take every alias with it
     * and close master's end of the socketpair. */
    int master_end = sv[0];
    check(quic_relay_del_conn(cids[0]) == 0,
          "quic_relay_del_conn removes the primary");
    check(fcntl(master_end, F_GETFD) < 0 && errno == EBADF,
          "teardown closed master's socketpair end");
    close(sv[1]);

    check(!quic_relay_forward(cids[0], sizeof(cids[0]), pkt, sizeof(pkt),
                              &peer1, c1len),
         "primary CID gone after teardown");
    check(!quic_relay_forward(cids[2], sizeof(cids[2]), pkt, sizeof(pkt),
                              &peer1, c1len),
         "spare pool CID gone too");
    check(!quic_relay_forward(dcid, sizeof(dcid), pkt, sizeof(pkt),
                              &peer1, c1len),
         "original dcid alias gone too");

    quic_relay_shutdown();

    printf("%d passed, %d failed\n", npass, nfail);
    return nfail ? 1 : 0;
}
