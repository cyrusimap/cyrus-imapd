/* quic_ebpf.c - eBPF-based per-connection QUIC dispatch for master */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "master/quic/quic_ebpf.h"

#ifdef HAVE_LIBBPF

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "util.h"

/* Services[]/nservices: quic_rebind_rendezvous_sockets() below is the
 * only thing in this file that needs master's own per-service state
 * directly, rather than just being called by it. */
#include "master/master.h"

#include "lib/xmalloc.h"

#ifndef CYR_QUIC_STEER_BPF_OBJ
#define CYR_QUIC_STEER_BPF_OBJ LIBEXEC_DIR "/cyr_quic_steer.bpf.o"
#endif

/* Reserved index for the rendezvous socket -- must match
 * QUIC_FALLBACK_INDEX in cyr_quic_steer.bpf.c. */
#define QUIC_FALLBACK_INDEX 0
#define QUIC_FIRST_REAL_INDEX 1

/* One per is_quic service -- s->quic_ebpf_ctx points at this. Holds
 * this service's own loaded copy of cyr_quic_steer.bpf.o: attaching
 * via SO_ATTACH_REUSEPORT_EBPF is scoped to whichever socket it's
 * attached to, so each service (each with its own rendezvous socket,
 * hence its own SO_REUSEPORT group) needs an independent load. */
struct quic_ebpf_service {
    struct bpf_object *obj;
    int cid_index_fd;      /* quic_cid_index map: CID -> index */
    int socks_fd;          /* quic_socks map: index -> socket */

    /* Index allocator for quic_socks. QUIC_FALLBACK_INDEX is permanently
     * reserved for the rendezvous socket; real connections get indices
     * from here, returned to free_list when a connection ends (see
     * quic_ebpf_del_sock()) rather than handed out once and never
     * reused. */
    uint32_t next_index;
    uint32_t *free_list;
    int nfree;
    int freecap;
};

static struct quic_ebpf_service *quic_ebpf_ctx(struct service *s)
{
    return (struct quic_ebpf_service *) s->quic_ebpf_ctx;
}

int quic_ebpf_init_service(struct service *s)
{
    struct quic_ebpf_service *ctx;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int cid_index_fd, socks_fd, prog_fd;
    uint32_t fallback_index = QUIC_FALLBACK_INDEX;

    /* Already attached: a reload re-runs this for every quic service,
     * but only a newly created one needs a program. Loading a second
     * would orphan the first -- still attached, its maps still locked
     * -- and lose the live connection state in them. */
    if (s->quic_ebpf_ctx) return 0;

    obj = bpf_object__open_file(CYR_QUIC_STEER_BPF_OBJ, NULL);
    if (!obj) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.object_open_failed",
                   lf_s("quic.bpf_obj", CYR_QUIC_STEER_BPF_OBJ),
                   lf_s("service.name", s->name));
        return -1;
    }
    if (bpf_object__load(obj)) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.load_failed",
                   lf_s("service.name", s->name));
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "cyr_quic_steer");
    cid_index_fd = bpf_object__find_map_fd_by_name(obj, "quic_cid_index");
    socks_fd = bpf_object__find_map_fd_by_name(obj, "quic_socks");
    if (!prog || cid_index_fd < 0 || socks_fd < 0) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.program_missing",
                   lf_s("quic.bpf_obj", CYR_QUIC_STEER_BPF_OBJ),
                   lf_s("service.name", s->name));
        bpf_object__close(obj);
        return -1;
    }

    {
        /* BPF_MAP_TYPE_REUSEPORT_SOCKARRAY's value is 8 bytes -- an
         * update with anything narrower (e.g. a plain `int`, whose
         * address has only 4 valid bytes) reads uninitialized stack
         * garbage into the high 32 bits and fails EINVAL. Zero-extend
         * explicitly. */
        uint64_t sock64 = (uint64_t) (unsigned int) s->socket;

        if (bpf_map_update_elem(socks_fd, &fallback_index, &sock64, BPF_ANY)) {
            xsyslog_ev(LOG_ERR, "quic.ebpf.fallback_register_failed",
                       lf_s("service.name", s->name));
            bpf_object__close(obj);
            return -1;
        }
    }

    prog_fd = bpf_program__fd(prog);
    if (setsockopt(s->socket, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                  &prog_fd, sizeof(prog_fd))) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.attach_failed",
                   lf_s("service.name", s->name),
                   lf_s("error", strerror(errno)));
        bpf_object__close(obj);
        return -1;
    }

    ctx = xzmalloc(sizeof(*ctx));
    ctx->obj = obj;
    ctx->cid_index_fd = cid_index_fd;
    ctx->socks_fd = socks_fd;
    ctx->next_index = QUIC_FIRST_REAL_INDEX;
    s->quic_ebpf_ctx = ctx;

    xsyslog_ev(LOG_INFO, "quic.ebpf.attached", lf_s("service.name", s->name));
    return 0;
}

/* Allocate an index for a new connection's socket, preferring a
 * previously-freed one over growing next_index -- see struct
 * quic_ebpf_service's comment. Returns 0 and fills *index on success,
 * -1 if the steering map is exhausted (2^32 - 2 connections'
 * worth of indices, in practice bounded by quic_socks' max_entries). */
static int quic_ebpf_alloc_index(struct quic_ebpf_service *ctx,
                                 int sock, uint32_t *index)
{
    uint32_t idx;

    /* NULL means quic_ebpf_init_service() never succeeded for this
     * service (quic_rebind_rendezvous_sockets() logs and moves on
     * rather than treating one service's failure as fatal for every
     * other one) -- fail this dispatch cleanly instead of dereferencing
     * a NULL ctx. */
    if (!ctx) return -1;

    if (ctx->nfree > 0) {
        idx = ctx->free_list[--ctx->nfree];
    }
    else {
        idx = ctx->next_index;
        if (idx == 0) return -1; /* wrapped: exhausted */
        ctx->next_index++;
    }

    {
        /* See quic_ebpf_init_service()'s comment on its own fallback
         * registration for why this must be a real zero-extended u64,
         * not a plain `int`. */
        uint64_t sock64 = (uint64_t) (unsigned int) sock;

        if (bpf_map_update_elem(ctx->socks_fd, &idx, &sock64, BPF_ANY)) {
            xsyslog_ev(LOG_ERR, "quic.ebpf.sock_register_failed");
            /* Put the index back rather than leak it. */
            if (ctx->nfree < ctx->freecap) {
                ctx->free_list[ctx->nfree++] = idx;
            }
            return -1;
        }
    }

    *index = idx;
    return 0;
}

int quic_ebpf_add_sock(struct service *s, int sock, uint32_t *index)
{
    struct quic_ebpf_service *ctx = quic_ebpf_ctx(s);

    return quic_ebpf_alloc_index(ctx, sock, index);
}

void quic_ebpf_del_sock(struct service *s, uint32_t index)
{
    struct quic_ebpf_service *ctx = quic_ebpf_ctx(s);

    if (!ctx || index == QUIC_FALLBACK_INDEX) return;

    if (ctx->nfree >= ctx->freecap) {
        ctx->freecap = ctx->freecap ? ctx->freecap * 2 : 64;
        ctx->free_list = xrealloc(ctx->free_list,
                                  (size_t) ctx->freecap * sizeof(uint32_t));
    }
    ctx->free_list[ctx->nfree++] = index;
}

int quic_ebpf_add_conn(struct service *s, const uint8_t cid[QUIC_CIDLEN],
                       uint32_t index)
{
    struct quic_ebpf_service *ctx = quic_ebpf_ctx(s);
    uint64_t key;

    memcpy(&key, cid, QUIC_CIDLEN);
    if (bpf_map_update_elem(ctx->cid_index_fd, &key, &index, BPF_NOEXIST)) {
        /* EEXIST just means BPF_NOEXIST caught a race on this CID --
         * expected, not an error (see quic_dispatch_connection()'s
         * dcid-retry comment in master.c for the common case that hits
         * this). Anything else is a real problem. */
        xsyslog_ev(errno == EEXIST ? LOG_DEBUG : LOG_ERR,
                   "quic.ebpf.conn_register_failed");
        return -1;
    }
    return 0;
}

int quic_ebpf_del_conn(struct service *s, const uint8_t cid[QUIC_CIDLEN])
{
    struct quic_ebpf_service *ctx = quic_ebpf_ctx(s);
    uint64_t key;

    if (!ctx) return -1;

    memcpy(&key, cid, QUIC_CIDLEN);
    return bpf_map_delete_elem(ctx->cid_index_fd, &key);
}

/* See "Privileges" in quic-dispatch.rst for why this is needed
 * (SO_REUSEPORT group membership requires an exact uid match). */
void quic_rebind_rendezvous_sockets(void)
{
    int i, on = 1;

    for (i = 0; i < nservices; i++) {
        struct service *s = &Services[i];
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);
        int newsock;

        /* Already set up: skip before touching the socket. Rebinding
         * a live rendezvous socket would strip the program attached to
         * it (quic_ebpf_init_service() below won't re-attach to a
         * service that has one) and drop packets mid-flight. */
        if (!s->is_quic || s->socket < 0 || s->quic_ebpf_ctx) continue;

        if (getsockname(s->socket, (struct sockaddr *) &sa, &salen)) {
            xsyslog_ev(LOG_ERR, "quic.rebind.getsockname_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
            continue;
        }

        newsock = socket(sa.ss_family, SOCK_DGRAM, 0);
        if (newsock < 0) {
            xsyslog_ev(LOG_ERR, "quic.rebind.socket_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
            continue;
        }

        if (setsockopt(newsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ||
            setsockopt(newsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
            xsyslog_ev(LOG_ERR, "quic.rebind.setsockopt_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
            close(newsock);
            continue;
        }
#if defined(IPV6_V6ONLY) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
        if (sa.ss_family == AF_INET6 &&
            setsockopt(newsock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) {
            xsyslog_ev(LOG_ERR, "quic.rebind.v6only_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
            close(newsock);
            continue;
        }
#endif
        if (bind(newsock, (struct sockaddr *) &sa, salen)) {
            xsyslog_ev(LOG_ERR, "quic.rebind.bind_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
            close(newsock);
            continue;
        }

        close(s->socket);
        s->socket = newsock;

        if (quic_ebpf_init_service(s)) {
            /* new connections will fail to dispatch for this service */
            xsyslog_ev(LOG_ERR, "quic.rebind.ebpf_init_failed",
                       lf_s("service.name", s->name),
                       lf_s("quic.family", s->familyname));
        }
    }
}

void quic_ebpf_shutdown_service(struct service *s)
{
    struct quic_ebpf_service *ctx = quic_ebpf_ctx(s);

    if (!ctx) return; /* quic_ebpf_init_service() never ran for s */

    bpf_object__close(ctx->obj);
    free(ctx->free_list);
    free(ctx);
    s->quic_ebpf_ctx = NULL;
}

int quic_keep_privs(void)
{
    /* A root -> non-root uid change clears the capability sets
     * entirely, and a non-root process can't get them back. Arm the
     * kernel to carry them across become_cyrus()'s setuid so that
     * quic_drop_privs() can pick what to keep afterwards. */
    if (prctl(PR_SET_KEEPCAPS, 1L)) {
        xsyslog_ev(LOG_ERR, "quic.privs.keepcaps_failed");
        return -1;
    }
    return 0;
}

int quic_drop_privs(void)
{
    cap_t caps;
    /* CAP_NET_ADMIN alone isn't enough to load a networking BPF
     * program (only to attach one): loading also needs CAP_BPF
     * (Linux >= 5.8), and cyr_quic_steer.bpf.c's pointer arithmetic
     * on the packet data pointer needs the verifier's
     * speculation-hardening relaxation, hence CAP_PERFMON. See
     * linux/capability.h above CAP_BPF's definition. All three are
     * used after the uid change, so all three must survive it. */
    cap_value_t keep[] = { CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_BPF,
                          CAP_PERFMON };

    /* PR_SET_KEEPCAPS carried the whole permitted set across the uid
     * change, CAP_SETUID/CAP_SETGID included -- narrow to keep[] now,
     * so a later bug here can't setuid(0) back to root. Fails if
     * quic_keep_privs() didn't run: nothing survived to narrow. */
    caps = cap_get_proc();
    if (!caps) {
        xsyslog_ev(LOG_ERR, "quic.privs.cap_get_failed");
        return -1;
    }
    if (cap_clear(caps) ||
        cap_set_flag(caps, CAP_PERMITTED, VECTOR_SIZE(keep), keep, CAP_SET) ||
        cap_set_flag(caps, CAP_EFFECTIVE, VECTOR_SIZE(keep), keep, CAP_SET) ||
        cap_set_proc(caps)) {
        xsyslog_ev(LOG_ERR, "quic.privs.cap_narrow_failed");
        cap_free(caps);
        return -1;
    }
    cap_free(caps);

    return 0;
}

#endif /* HAVE_LIBBPF */
