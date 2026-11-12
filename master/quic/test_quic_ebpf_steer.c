/* Standalone smoke test for cyr_quic_steer.bpf.o: attach it to a
 * rendezvous socket the way quic_ebpf_init_service() does, register two
 * unconnected per-connection sockets under a pool of CIDs (see
 * QUIC_CID_POOL_SIZE), then confirm the kernel steers crafted QUIC
 * packets by CID -- to the right one of the two whatever address sent
 * them, which is what migration depends on, and to the rendezvous
 * socket for a CID nothing registered.
 *
 * Two targets rather than one so the checks can't pass by luck: the
 * kernel's default reuseport hash is per 4-tuple, so without this
 * program every packet from one sender lands on the same socket. Only
 * real CID steering sends two CIDs from one sender to two sockets.
 *
 * Needs CAP_BPF and CAP_PERFMON, so run it as root. Not part of the
 * build; ad hoc verification only:
 *
 *   cc -o test_quic_ebpf_steer test_quic_ebpf_steer.c -lbpf
 *   sudo ./test_quic_ebpf_steer     # from the directory holding
 *                                   # cyr_quic_steer.bpf.o
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define RENDEZ_PORT 18443
#define TEST_CID_POOL_SIZE 3
#define CIDLEN 8

/* Must match cyr_quic_steer.bpf.c. */
#define QUIC_FALLBACK_INDEX 0
#define TARGET_A_INDEX 1
#define TARGET_B_INDEX 2

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

/* A socket in the rendezvous port's SO_REUSEPORT group, deliberately
 * left unconnected -- the same shape as master's per-connection socket,
 * so a migrated client's packets from a new address still arrive. */
static int bind_reuseport(void)
{
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                .sin_port = htons(RENDEZ_PORT) };
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    int one = 1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) { perror("socket"); exit(1); }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) {
        perror("SO_REUSEPORT"); exit(1);
    }
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind"); exit(1);
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* quic_socks is a REUSEPORT_SOCKARRAY, whose value is 8 bytes: an
 * update from a plain int reads uninitialized stack into the high half
 * and fails EINVAL. Same zero-extension quic_ebpf.c does. */
static int register_sock(int socks_fd, uint32_t index, int sock)
{
    uint64_t sock64 = (uint64_t) (unsigned int) sock;

    return bpf_map_update_elem(socks_fd, &index, &sock64, BPF_ANY);
}

/* Send a short-header QUIC-shaped packet carrying cid, then report
 * whether it landed on want and not on other. */
static void send_and_check(int from, const uint8_t cid[CIDLEN],
                           int want, const int *others, int nothers,
                           const char *label)
{
    unsigned char pkt[16];
    unsigned char buf[64];
    struct sockaddr_in dst = { .sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                               .sin_port = htons(RENDEZ_PORT) };
    struct sockaddr_in from_addr;
    socklen_t fromlen = sizeof(from_addr);
    char label_buf[160];
    ssize_t n;
    int i;

    pkt[0] = 0x40; /* short header, bit7=0 */
    memcpy(pkt + 1, cid, CIDLEN);
    memset(pkt + 1 + CIDLEN, 0xAA, sizeof(pkt) - 1 - CIDLEN);

    if (sendto(from, pkt, sizeof(pkt), 0,
               (struct sockaddr *) &dst, sizeof(dst)) < 0) {
        perror("sendto");
        exit(1);
    }
    usleep(100000);

    snprintf(label_buf, sizeof(label_buf),
             "%s: landed on the right socket", label);
    n = recvfrom(want, buf, sizeof(buf), MSG_DONTWAIT,
                 (struct sockaddr *) &from_addr, &fromlen);
    check(n > 0, label_buf);
    if (n > 0) {
        printf("      (from %s:%u)\n", inet_ntoa(from_addr.sin_addr),
               ntohs(from_addr.sin_port));
    }

    snprintf(label_buf, sizeof(label_buf),
             "%s: and on no other socket", label);
    for (i = 0; i < nothers; i++) {
        if (recvfrom(others[i], buf, sizeof(buf), MSG_DONTWAIT,
                     NULL, NULL) > 0) {
            check(0, label_buf);
            return;
        }
    }
    check(1, label_buf);
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int cid_index_fd, socks_fd, prog_fd;
    int rendez, target_a, target_b, sender1, sender2;
    int i;

    /* master pre-registers a whole pool at dispatch time, so a
     * migrating client's fresh CID is routable the moment it's used. */
    uint8_t cids[TEST_CID_POOL_SIZE][CIDLEN] = {
        { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 },
        { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xf0, 0x0d },
    };
    uint8_t unknown_cid[CIDLEN] = { 0, 0, 0, 0, 0, 0, 0, 0xff };

    obj = bpf_object__open_file("cyr_quic_steer.bpf.o", NULL);
    if (!obj) { perror("open_file"); return 1; }
    if (bpf_object__load(obj)) { perror("load"); return 1; }

    prog = bpf_object__find_program_by_name(obj, "cyr_quic_steer");
    cid_index_fd = bpf_object__find_map_fd_by_name(obj, "quic_cid_index");
    socks_fd = bpf_object__find_map_fd_by_name(obj, "quic_socks");
    if (!prog || cid_index_fd < 0 || socks_fd < 0) {
        fprintf(stderr, "prog=%p cid_index=%d socks=%d\n",
                (void *) prog, cid_index_fd, socks_fd);
        return 1;
    }

    /* Rendezvous socket first: it owns the reuseport group, is the
     * fallback at index 0, and is what the program attaches to. */
    rendez = bind_reuseport();
    if (register_sock(socks_fd, QUIC_FALLBACK_INDEX, rendez)) {
        perror("register rendezvous socket"); return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (setsockopt(rendez, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                   &prog_fd, sizeof(prog_fd))) {
        perror("SO_ATTACH_REUSEPORT_EBPF"); return 1;
    }
    printf("attached to the rendezvous socket OK\n");

    target_a = bind_reuseport();
    target_b = bind_reuseport();
    if (register_sock(socks_fd, TARGET_A_INDEX, target_a) ||
        register_sock(socks_fd, TARGET_B_INDEX, target_b)) {
        perror("register target socket"); return 1;
    }

    /* cids[0] and cids[1] are one connection's pool, cids[2] a second
     * connection's -- so a CID change and a socket change coincide. */
    for (i = 0; i < TEST_CID_POOL_SIZE; i++) {
        uint64_t key;
        uint32_t index = (i < 2) ? TARGET_A_INDEX : TARGET_B_INDEX;

        memcpy(&key, cids[i], CIDLEN);
        if (bpf_map_update_elem(cid_index_fd, &key, &index, BPF_NOEXIST)) {
            perror("register CID"); return 1;
        }
    }
    printf("target A fd=%d (2 CIDs), target B fd=%d (1 CID)\n",
           target_a, target_b);

    /* sender1 is the client; sender2 is the same client after it has
     * migrated to a different source address:port. */
    sender1 = socket(AF_INET, SOCK_DGRAM, 0);
    sender2 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender1 < 0 || sender2 < 0) { perror("sender socket"); return 1; }

    {
        int not_a[] = { rendez, target_b };
        int not_b[] = { rendez, target_a };
        int not_r[] = { target_a, target_b };

        send_and_check(sender1, cids[0], target_a, not_a, 2,
                       "primary CID, pre-migration");

        /* Same sender, a CID belonging to the other connection: the
         * default hash could not tell these two apart. */
        send_and_check(sender1, cids[2], target_b, not_b, 2,
                       "other connection's CID, same sender");

        /* A spare CID from the first pool, still the first sender. */
        send_and_check(sender1, cids[1], target_a, not_a, 2,
                       "spare CID, pre-migration");

        /* Migrated, but still addressing the CID it started with. */
        send_and_check(sender2, cids[0], target_a, not_a, 2,
                       "primary CID, post-migration source");

        /* Migrated and switched to a fresh CID at once, which is what
         * RFC 9000 recommends. */
        send_and_check(sender2, cids[1], target_a, not_a, 2,
                       "spare CID, post-migration source");

        /* A CID nothing registered is the new-connection case: it must
         * reach the rendezvous socket, not some live connection's. */
        send_and_check(sender1, unknown_cid, rendez, not_r, 2,
                       "unregistered CID falls back to rendezvous");
    }

    printf("%d passed, %d failed\n", npass, nfail);
    return nfail ? 1 : 0;
}
