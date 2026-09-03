/* Standalone smoke test for cyr_quic_steer.bpf.o: attach it to lo via
 * the exact libbpf TC API master.c will use, populate the sockhash
 * with a real connected UDP socket keyed by an 8-byte CID, send a
 * crafted short-header QUIC packet at the "rendezvous" socket's
 * port, and confirm the kernel delivers it to the assigned socket
 * instead. Not part of the build -- ad hoc verification only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, port_map_fd, conns_map_fd;
    int ifindex = if_nametoindex("lo");
    struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = ifindex,
                                 .attach_point = BPF_TC_INGRESS };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    int rv;

    obj = bpf_object__open_file("cyr_quic_steer.bpf.o", NULL);
    if (!obj) { perror("open_file"); return 1; }
    if (bpf_object__load(obj)) { perror("load"); return 1; }

    prog = bpf_object__find_program_by_name(obj, "cyr_quic_steer");
    if (!prog) { fprintf(stderr, "no prog\n"); return 1; }
    prog_fd = bpf_program__fd(prog);

    port_map_fd = bpf_object__find_map_fd_by_name(obj, "quic_port");
    conns_map_fd = bpf_object__find_map_fd_by_name(obj, "quic_conns");
    if (port_map_fd < 0 || conns_map_fd < 0) {
        fprintf(stderr, "map fds: port=%d conns=%d\n",
               port_map_fd, conns_map_fd);
        return 1;
    }

    rv = bpf_tc_hook_create(&hook);
    if (rv && rv != -EEXIST) {
        fprintf(stderr, "hook_create: %d\n", rv); return 1;
    }

    opts.prog_fd = prog_fd;
    rv = bpf_tc_attach(&hook, &opts);
    if (rv) { fprintf(stderr, "tc_attach: %d\n", rv); return 1; }
    printf("attached OK, prog_id=%u\n", opts.prog_id);

    /* rendezvous socket: bound, NOT connected, on port 18443 */
    int rendez = socket(AF_INET, SOCK_DGRAM, 0);
    int rone = 1;
    setsockopt(rendez, SOL_SOCKET, SO_REUSEPORT, &rone, sizeof(rone));
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                 .sin_port = htons(18443) };
    if (bind(rendez, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind rendez"); return 1;
    }

    __u32 port_key = 0, port_val = 18443;
    if (bpf_map_update_elem(port_map_fd, &port_key, &port_val, BPF_ANY)) {
        perror("update port map"); return 1;
    }

    /* target socket: deliberately on a DIFFERENT, unprivileged,
     * kernel-assigned port -- testing whether bpf_sk_assign() from a
     * TC program requires the assigned socket to match the packet's
     * own destination port (unlike the SK_LOOKUP overload, which
     * documents that the assigned socket must be "compatible with
     * the packet description"). */
    int target = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in taddr = { .sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                  .sin_port = htons(0) };
    if (bind(target, (struct sockaddr *)&taddr, sizeof(taddr))) {
        perror("bind target"); return 1;
    }
    socklen_t talen = sizeof(taddr);
    getsockname(target, (struct sockaddr *)&taddr, &talen);
    printf("target socket bound to ephemeral port %u\n",
          ntohs(taddr.sin_port));

    __u64 cid = 0x1122334455667788ULL;
    if (bpf_map_update_elem(conns_map_fd, &cid, &target, BPF_NOEXIST)) {
        perror("sockhash update"); return 1;
    }
    printf("inserted target socket fd=%d into sockhash under cid\n", target);

    /* sender: a third socket, sends a short-header QUIC-shaped UDP
     * packet whose first 8 bytes after the 1-byte header equal cid. */
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned char pkt[16];
    pkt[0] = 0x40; /* short header, bit7=0 */
    memcpy(pkt+1, &cid, 8);
    memset(pkt+9, 0xAA, sizeof(pkt)-9);

    struct sockaddr_in dst = { .sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                               .sin_port = htons(18443) };
    if (sendto(sender, pkt, sizeof(pkt), 0,
              (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto"); return 1;
    }

    usleep(100000);

    unsigned char buf[64];
    struct timeval tv = { .tv_usec = 200000 };
    setsockopt(target, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(rendez, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(target, buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) {
        printf("PASS: target socket received %zd bytes (steered correctly)\n",
              n);
    }
    else {
        printf("target socket got nothing (errno=%d)\n", errno);
    }

    n = recv(rendez, buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) {
        printf("FAIL?: rendezvous socket ALSO/INSTEAD received %zd bytes\n",
              n);
    }
    else {
        printf("rendezvous socket got nothing (errno=%d) -- good, "
              "steered away\n", errno);
    }

    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
    return 0;
}
