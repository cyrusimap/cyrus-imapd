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
#include <net/if.h>
#include <pwd.h>
#include <grp.h>
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

#include "lib/strarray.h"
#include "lib/xmalloc.h"

#ifndef CYR_QUIC_STEER_BPF_OBJ
#define CYR_QUIC_STEER_BPF_OBJ LIBEXEC_DIR "/cyr_quic_steer.bpf.o"
#endif

static struct bpf_object *quic_bpf_obj;
static int quic_conns_map_fd = -1;
static int quic_port_map_fd = -1;
/* One entry per interface cyr_quic_steer ended up attached to --
 * quic_ebpf_shutdown() needs all of them to detach cleanly, since the
 * clsact qdisc (and our filter on it) is per-interface even though
 * the loaded program/maps above are shared. */
static struct bpf_tc_hook *quic_hooks;
static int quic_nhooks;

/* Attach prog to ifname's TC ingress hook, appending the result to
 * quic_hooks[] on success (quic_ebpf_shutdown() undoes it later).
 * required only affects the log level (LOG_ERR vs LOG_WARNING):
 * explicit-list callers treat a failure here as fatal and unwind via
 * quic_ebpf_shutdown(), best-effort auto-discovery just moves on.
 * Returns 0 on success. */
static int quic_ebpf_attach_one(struct bpf_program *prog, const char *ifname,
                                int required)
{
    int level = required ? LOG_ERR : LOG_WARNING;
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    int ifindex, rv;

    ifindex = (int) if_nametoindex(ifname);
    if (!ifindex) {
        xsyslog_ev(level, "quic.ebpf.iface_index_failed",
                   lf_s("quic.iface", ifname));
        return -1;
    }

    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    rv = bpf_tc_hook_create(&hook);
    if (rv && rv != -EEXIST) {
        xsyslog_ev(level, "quic.ebpf.tc_hook_create_failed",
                   lf_s("quic.iface", ifname),
                   lf_s("error", strerror(-rv)));
        return -1;
    }

    opts.prog_fd = bpf_program__fd(prog);
    rv = bpf_tc_attach(&hook, &opts);
    if (rv) {
        xsyslog_ev(level, "quic.ebpf.tc_attach_failed",
                   lf_s("quic.iface", ifname),
                   lf_s("error", strerror(-rv)));
        /* We created the qdisc above (or found one already there) but
         * couldn't attach our filter to it -- don't leave a bare
         * clsact qdisc behind on an interface we're otherwise not
         * touching. Same ingress|egress-override rationale as
         * quic_ebpf_shutdown(). */
        hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
        bpf_tc_hook_destroy(&hook);
        return -1;
    }

    quic_hooks = xrealloc(quic_hooks,
                          (size_t) (quic_nhooks + 1) * sizeof(*quic_hooks));
    quic_hooks[quic_nhooks++] = hook;

    xsyslog_ev(LOG_INFO, "quic.ebpf.attached", lf_s("quic.iface", ifname));
    return 0;
}

int quic_ebpf_init(const char *ifnames)
{
    struct bpf_program *prog;

    quic_bpf_obj = bpf_object__open_file(CYR_QUIC_STEER_BPF_OBJ, NULL);
    if (!quic_bpf_obj) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.object_open_failed",
                   lf_s("quic.bpf_obj", CYR_QUIC_STEER_BPF_OBJ));
        return -1;
    }
    if (bpf_object__load(quic_bpf_obj)) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.load_failed");
        return -1;
    }

    prog = bpf_object__find_program_by_name(quic_bpf_obj, "cyr_quic_steer");
    if (!prog) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.program_missing",
                   lf_s("quic.bpf_obj", CYR_QUIC_STEER_BPF_OBJ));
        return -1;
    }

    quic_conns_map_fd =
        bpf_object__find_map_fd_by_name(quic_bpf_obj, "quic_conns");
    quic_port_map_fd =
        bpf_object__find_map_fd_by_name(quic_bpf_obj, "quic_port");
    if (quic_conns_map_fd < 0 || quic_port_map_fd < 0) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.maps_missing",
                   lf_s("quic.bpf_obj", CYR_QUIC_STEER_BPF_OBJ));
        return -1;
    }

    if (ifnames && *ifnames) {
        /* Explicit list: every named interface is required -- fail
         * (and unwind whatever we did attach) rather than leave QUIC
         * silently unreachable on just the one the admin made a typo
         * on. */
        strarray_t *names = strarray_split(ifnames, " ", STRARRAY_TRIM);
        int i, failed = 0;

        for (i = 0; i < strarray_size(names); i++) {
            if (quic_ebpf_attach_one(prog, strarray_nth(names, i), 1))
                failed = 1;
        }
        strarray_free(names);

        if (failed) {
            quic_ebpf_shutdown();
            return -1;
        }
    }
    else {
        /* No interface list configured: attach to every interface this
         * host currently has, best-effort -- an interface that fails
         * to attach (unusual/virtual, down, ...) is logged and
         * skipped, since the alternative is a working host held
         * hostage by one uncooperative interface nothing here actually
         * needs. */
        struct if_nameindex *ifs = if_nameindex();
        struct if_nameindex *p;

        if (!ifs) {
            xsyslog_ev(LOG_ERR, "quic.ebpf.iface_enum_failed");
            return -1;
        }
        for (p = ifs; p->if_index; p++) {
            quic_ebpf_attach_one(prog, p->if_name, 0);
        }
        if_freenameindex(ifs);

        if (!quic_nhooks) {
            xsyslog_ev(LOG_ERR, "quic.ebpf.no_iface_attached");
            return -1;
        }
    }

    return 0;
}

int quic_ebpf_add_port(uint16_t port)
{
    uint32_t key = port;
    uint8_t val = 1;

    /* BPF_ANY: harmless/idempotent if called twice for the same port
     * (e.g. a service's ipv4 and ipv6 Services[] entries, which share
     * one port) -- the value carries no information beyond presence. */
    if (bpf_map_update_elem(quic_port_map_fd, &key, &val, BPF_ANY)) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.port_register_failed",
                   lf_u("quic.port", port));
        return -1;
    }
    return 0;
}

int quic_ebpf_add_conn(const uint8_t cid[QUIC_EBPF_CIDLEN], int sock)
{
    uint64_t key;

    memcpy(&key, cid, QUIC_EBPF_CIDLEN);
    if (bpf_map_update_elem(quic_conns_map_fd, &key, &sock, BPF_NOEXIST)) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.conn_register_failed");
        return -1;
    }
    return 0;
}

int quic_ebpf_del_conn(const uint8_t cid[QUIC_EBPF_CIDLEN])
{
    uint64_t key;

    memcpy(&key, cid, QUIC_EBPF_CIDLEN);
    return bpf_map_delete_elem(quic_conns_map_fd, &key);
}

int quic_ebpf_set_fallback(int family, uint16_t port, int sock)
{
    /* Must match master/quic/cyr_quic_steer.bpf.c's steer()'s fallback_key
     * formula: (port << 1) | family bit. */
    uint64_t key = ((uint64_t) port << 1) | (family == AF_INET6 ? 1 : 0);

    /* BPF_ANY, not BPF_NOEXIST: unlike quic_ebpf_add_conn()'s
     * per-connection keys (each expected to be genuinely new),
     * calling this again for the same port/family is a deliberate
     * replace -- master's rendezvous socket for a port/family only
     * ever changes when master itself restarts, at which point the
     * old map (and everything in it) is long gone anyway. */
    if (bpf_map_update_elem(quic_conns_map_fd, &key, &sock, BPF_ANY)) {
        xsyslog_ev(LOG_ERR, "quic.ebpf.fallback_register_failed");
        return -1;
    }
    return 0;
}

/* Every socket joining a common SO_REUSEPORT group must be bound
 * under the same effective UID -- verified empirically against this
 * kernel: a SO_REUSEPORT bind from a different uid than the group's
 * existing members fails EADDRINUSE, even with SO_REUSEPORT/
 * IPV6_V6ONLY/CAP_NET_BIND_SERVICE all correct. Each proto="quic"
 * rendezvous socket was bound at startup while master was still root;
 * quic_dispatch_connection()'s per-connection sockets are created as
 * cyrus (what master runs as by the time a connection arrives). So:
 * close and re-bind each rendezvous socket here, now that master is
 * cyrus too, or every dispatch hits that same EADDRINUSE joining a
 * group whose only member is still root's. */
void quic_rebind_rendezvous_sockets(void)
{
    int i, on = 1;

    for (i = 0; i < nservices; i++) {
        struct service *s = &Services[i];
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);
        int newsock;

        if (!s->is_quic || s->socket < 0) continue;

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

        {
            uint16_t port = (sa.ss_family == AF_INET6) ?
                ntohs(((struct sockaddr_in6 *) &sa)->sin6_port) :
                ntohs(((struct sockaddr_in *) &sa)->sin_port);

            if (quic_ebpf_set_fallback(sa.ss_family, port, newsock)) {
                /* new connections may be misdirected to an unrelated
                 * existing one */
                xsyslog_ev(LOG_ERR, "quic.rebind.fallback_register_failed",
                           lf_s("service.name", s->name),
                           lf_s("quic.family", s->familyname));
            }
        }
    }
}

int quic_ebpf_shutdown(void)
{
    int i, rv, ret = 0;

    if (!quic_bpf_obj) return 0; /* quic_ebpf_init() never ran */

    /* bpf_tc_hook_destroy() only removes the clsact qdisc itself (vs.
     * just our filter) when attach_point covers both directions --
     * verified against libbpf's own code: a lone BPF_TC_INGRESS/EGRESS
     * just detaches the filter. Since each qdisc exists solely for
     * cyr_quic_steer, override attach_point on a copy of each hook
     * (all attached at ingress only) to take the whole thing down.
     * -ENOENT means it's already gone (e.g. removed by hand) -- fine,
     * that's the end state we want. */
    for (i = 0; i < quic_nhooks; i++) {
        struct bpf_tc_hook hook = quic_hooks[i];

        hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
        rv = bpf_tc_hook_destroy(&hook);
        if (rv && rv != -ENOENT) {
            xsyslog_ev(LOG_ERR, "quic.ebpf.tc_hook_destroy_failed",
                       lf_s("error", strerror(-rv)));
            ret = -1;
        }
    }
    free(quic_hooks);
    quic_hooks = NULL;
    quic_nhooks = 0;

    bpf_object__close(quic_bpf_obj);
    quic_bpf_obj = NULL;
    quic_conns_map_fd = -1;
    quic_port_map_fd = -1;

    return ret;
}

int quic_drop_privs(void)
{
    struct passwd *p;
    struct group *g;
    uid_t newuid;
    gid_t newgid;
    cap_t caps;
    cap_value_t keep[] = { CAP_NET_BIND_SERVICE, CAP_NET_ADMIN };
    const char *cyrus = cyrus_user();
    const char *mail = cyrus_group();

    p = getpwnam(cyrus);
    if (!p) {
        xsyslog_ev(LOG_ERR, "quic.privs.user_lookup_failed",
                   lf_s("quic.user", cyrus));
        return -1;
    }
    newuid = p->pw_uid;
    newgid = p->pw_gid;

    if (mail) {
        g = getgrnam(mail);
        if (!g) {
            xsyslog_ev(LOG_ERR, "quic.privs.group_lookup_failed",
                       lf_s("quic.group", mail));
            return -1;
        }
        newgid = g->gr_gid;
    }

    /* Without this, the upcoming uid transition (root -> non-root)
     * clears our capability sets entirely, same as become_cyrus().
     * We want that clearing to happen under OUR control instead, a
     * few lines down, once we've picked exactly what to keep. */
    if (prctl(PR_SET_KEEPCAPS, 1L)) {
        xsyslog_ev(LOG_ERR, "quic.privs.keepcaps_failed");
        return -1;
    }

    if (initgroups(cyrus, newgid)) {
        xsyslog_ev(LOG_ERR, "quic.privs.initgroups_failed");
        return -1;
    }
    if (setgid(newgid)) {
        xsyslog_ev(LOG_ERR, "quic.privs.setgid_failed");
        return -1;
    }
    if (setuid(newuid)) {
        xsyslog_ev(LOG_ERR, "quic.privs.setuid_failed");
        return -1;
    }

    /* KEEPCAPS means our capability sets survived the uid transition
     * above -- we still hold everything root had, including
     * CAP_SETUID/CAP_SETGID. Narrow down immediately to just the two
     * capabilities QUIC dispatch and its shutdown cleanup need;
     * dropping CAP_SETUID here is what prevents a later bug in this
     * now-unprivileged process from setuid(0)'ing back to root. */
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
